const { pool } = require('../database');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const Joi = require('joi');
const { handleError } = require('../utils/errorHandler');

// Validation schemas
const createUserSchema = Joi.object({
  first_name: Joi.string().max(100).required(),
  last_name: Joi.string().max(100).required(),
  username: Joi.string().max(255).required(),
  email: Joi.string().email().max(255).required(),
  password: Joi.string().min(8).required(),
  security_question_1: Joi.string().optional(),
  security_answer_1: Joi.string().optional(),
  security_question_2: Joi.string().optional(),
  security_answer_2: Joi.string().optional(),
  two_factor_enabled: Joi.boolean().default(false),
  token_expiration_minutes: Joi.number().integer().min(1).max(1440).default(60)
});

const updateUserSchema = Joi.object({
  first_name: Joi.string().max(100).optional(),
  last_name: Joi.string().max(100).optional(),
  username: Joi.string().max(255).optional(),
  email: Joi.string().email().max(255).optional(),
  password: Joi.string().min(8).optional(),
  account_status: Joi.string().valid('active', 'inactive', 'locked').optional(),
  security_question_1: Joi.string().optional(),
  security_answer_1: Joi.string().optional(),
  security_question_2: Joi.string().optional(),
  security_answer_2: Joi.string().optional(),
  two_factor_enabled: Joi.boolean().optional(),
  token_expiration_minutes: Joi.number().integer().min(1).max(1440).optional(),
  toggleTwoFactor: Joi.boolean().optional()
});

// Helper functions
const generateSalt = () => crypto.randomBytes(32).toString('hex');

const hashPassword = async (password, salt) => {
  return await bcrypt.hash(password + salt, 12);
};

const hashSecurityAnswer = async (answer, salt) => {
  if (!answer) return null;
  return await bcrypt.hash(answer.toLowerCase().trim() + salt, 12);
};

const generateTwoFactorSecret = () => {
  return speakeasy.generateSecret({
    name: 'SecureAccess',
    length: 32
  }).base32;
};

// Get all users
const getAllUsers = async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email, 
        account_creation_date, last_login_timestamp, account_status,
        two_factor_enabled, jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, created_at, updated_at
      FROM sa_users 
      ORDER BY created_at DESC
    `);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    handleError(error, res, 'fetch users');
  }
};

// Get user by ID
const getUserById = async (req, res) => {
  try {
    // Use user ID from JWT token if accessing /me endpoint
    const { id } = req.params;
    const userId = id || req.user?.userId;
    
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID required'
      });
    }
    
    const [rows] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email,
        account_creation_date, last_login_timestamp, account_status,
        security_question_1, security_question_2, two_factor_enabled,
        jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, created_at, updated_at
      FROM sa_users 
      WHERE user_id = ?
    `, [userId]);
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    handleError(error, res, 'fetch user');
  }
};

// Create new user
const createUser = async (req, res) => {
  try {
    const { error, value } = createUserSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const {
      first_name, last_name, username, email, password,
      security_question_1, security_answer_1,
      security_question_2, security_answer_2,
      two_factor_enabled, token_expiration_minutes
    } = value;

    // Check for existing username or email
    const [existingUsers] = await pool.execute(`
      SELECT user_id FROM sa_users WHERE username = ? OR email = ?
    `, [username, email]);

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists'
      });
    }

    // Generate salt and hash password
    const salt = generateSalt();
    const master_password_hash = await hashPassword(password, salt);
    
    // Hash security answers if provided
    const security_answer_1_hash = await hashSecurityAnswer(security_answer_1, salt);
    const security_answer_2_hash = await hashSecurityAnswer(security_answer_2, salt);
    
    // Generate 2FA secret if enabled
    const two_factor_secret = two_factor_enabled ? generateTwoFactorSecret() : null;

    const insertParams = [
      first_name,
      last_name,
      username,
      email,
      master_password_hash,
      salt,
      security_question_1 || null,
      security_answer_1_hash,
      security_question_2 || null,
      security_answer_2_hash,
      two_factor_enabled ? 1 : 0,
      two_factor_secret,
      token_expiration_minutes
    ];

    const [result] = await pool.execute(`
      INSERT INTO sa_users (
        first_name, last_name, username, email, master_password_hash, salt,
        security_question_1, security_answer_1_hash,
        security_question_2, security_answer_2_hash,
        two_factor_enabled, two_factor_secret, token_expiration_minutes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, insertParams);
    
    // Fetch the created user (without sensitive data)
    const [newUser] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email,
        account_creation_date, account_status, security_question_1,
        security_question_2, two_factor_enabled, jwt_secret_version,
        refresh_token_rotation_enabled, token_expiration_minutes,
        created_at, updated_at
      FROM sa_users 
      WHERE user_id = ?
    `, [result.insertId]);
    
    const response = {
      success: true,
      message: 'User created successfully',
      data: newUser[0]
    };

    // Include 2FA setup info if enabled
    if (two_factor_enabled && two_factor_secret) {
      response.twoFactorSetup = {
        secret: two_factor_secret,
        qrCodeUrl: speakeasy.otpauthURL({
          secret: two_factor_secret,
          label: username,
          name: 'SecureAccess',
          issuer: 'SecureAccess'
        })
      };
    }
    
    res.status(201).json(response);
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists'
      });
    }
    handleError(error, res, 'create user');
  }
};

// Update user
const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    
    // Handle profile update authentication
    let userId = id;
    if (!userId && req.user) {
      userId = req.user.userId; // From JWT token
    }
    
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID required'
      });
    }
    
    // Allow users to only update their own profile (unless admin)
    if (req.user.role !== 'Admin' && req.user.userId.toString() !== userId.toString()) {
      return res.status(403).json({
        success: false,
        message: 'You can only update your own profile'
      });
    }
    
    const { error, value } = updateUserSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    // Check if user exists and get current data
    const [existingUser] = await pool.execute(`
      SELECT user_id, salt, two_factor_enabled, two_factor_secret 
      FROM sa_users WHERE user_id = ?
    `, [userId]);
    
    if (existingUser.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = existingUser[0];
    const salt = user.salt;
    const updates = [];
    const values = [];

    // Helper function to add simple field updates
    const addUpdate = (field, dbColumn, value) => {
      if (value !== undefined) {
        updates.push(`${dbColumn} = ?`);
        values.push(value);
      }
    };

    // Handle each field update
    const {
      first_name, last_name, username, email, password, account_status,
      security_question_1, security_answer_1,
      security_question_2, security_answer_2,
      two_factor_enabled, token_expiration_minutes, toggleTwoFactor
    } = value;

    addUpdate('first_name', 'first_name', first_name);
    addUpdate('last_name', 'last_name', last_name);
    addUpdate('username', 'username', username);
    addUpdate('email', 'email', email);
    addUpdate('account_status', 'account_status', account_status);
    addUpdate('security_question_1', 'security_question_1', security_question_1);
    addUpdate('security_question_2', 'security_question_2', security_question_2);
    addUpdate('token_expiration_minutes', 'token_expiration_minutes', token_expiration_minutes);
    
    if (password !== undefined) {
      const master_password_hash = await hashPassword(password, salt);
      updates.push('master_password_hash = ?');
      values.push(master_password_hash);
      // Increment JWT secret version on password change
      updates.push('jwt_secret_version = jwt_secret_version + 1');
    }
    if (security_answer_1 !== undefined) {
      const security_answer_1_hash = await hashSecurityAnswer(security_answer_1, salt);
      updates.push('security_answer_1_hash = ?');
      values.push(security_answer_1_hash);
    }
    if (security_answer_2 !== undefined) {
      const security_answer_2_hash = await hashSecurityAnswer(security_answer_2, salt);
      updates.push('security_answer_2_hash = ?');
      values.push(security_answer_2_hash);
    }

    // Handle 2FA toggle or direct setting
    let newTwoFactorSecret = null;
    if (toggleTwoFactor === true) {
      // Toggle current 2FA state
      const newTwoFactorEnabled = !user.two_factor_enabled;
      updates.push('two_factor_enabled = ?');
      values.push(newTwoFactorEnabled ? 1 : 0);
      
      if (newTwoFactorEnabled) {
        newTwoFactorSecret = generateTwoFactorSecret();
        updates.push('two_factor_secret = ?');
        values.push(newTwoFactorSecret);
      } else {
        updates.push('two_factor_secret = ?');
        values.push(null);
      }
    } else if (two_factor_enabled !== undefined) {
      // Direct 2FA setting
      updates.push('two_factor_enabled = ?');
      values.push(two_factor_enabled ? 1 : 0);
      
      if (two_factor_enabled) {
        newTwoFactorSecret = generateTwoFactorSecret();
        updates.push('two_factor_secret = ?');
        values.push(newTwoFactorSecret);
      } else {
        updates.push('two_factor_secret = ?');
        values.push(null);
      }
    }
    
    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No fields to update'
      });
    }

    // Add updated timestamp
    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(userId);
    
    await pool.execute(
      `UPDATE sa_users SET ${updates.join(', ')} WHERE user_id = ?`,
      values
    );
    
    // Fetch updated user
    const [updatedUser] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email,
        account_creation_date, last_login_timestamp, account_status,
        security_question_1, security_question_2, two_factor_enabled,
        jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, created_at, updated_at
      FROM sa_users 
      WHERE user_id = ?
    `, [userId]);

    const responseData = {
      success: true,
      message: 'User updated successfully',
      data: updatedUser[0]
    };

    // If 2FA was enabled during this update, include setup info
    if (newTwoFactorSecret) {
      responseData.twoFactorSetup = {
        secret: newTwoFactorSecret,
        qrCodeUrl: speakeasy.otpauthURL({
          secret: newTwoFactorSecret,
          label: updatedUser[0].username,
          name: 'SecureAccess',
          issuer: 'SecureAccess'
        })
      };
    }
    
    res.json(responseData);
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists'
      });
    }
    handleError(error, res, 'update user');
  }
};

// Update last login timestamp
const updateLastLogin = async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await pool.execute(
      'UPDATE sa_users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
      [id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Last login timestamp updated successfully'
    });
  } catch (error) {
    handleError(error, res, 'update last login');
  }
};

// Delete user
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await pool.execute('DELETE FROM sa_users WHERE user_id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    handleError(error, res, 'delete user');
  }
};

// Get user security info (for password reset, etc.)
const getUserSecurity = async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(`
      SELECT 
        user_id, username, email, security_question_1, security_question_2,
        two_factor_enabled, account_status
      FROM sa_users 
      WHERE user_id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    handleError(error, res, 'fetch user security info');
  }
};

module.exports = {
  getAllUsers,
  getUserById,
  createUser,
  updateUser,
  updateLastLogin,
  deleteUser,
  getUserSecurity
};
// Improved auth controller with proper response structure
const { pool } = require('../database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { handleError } = require('../utils/errorHandler');

// Simple login function with proper response structure
const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }
    
    // Query the database for the actual user
    const query = 'SELECT user_id, first_name, last_name, username, email, account_status, two_factor_enabled, last_login_timestamp, master_password_hash, salt, role FROM sa_users WHERE username = ? OR email = ?';
    
    const [rows] = await pool.execute(query, [username, username]);
    
    if (rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    // Create user object from database result
    const user = {
        user_id: rows[0].user_id,
        username: rows[0].username,
        email: rows[0].email,
        role: rows[0].role
    };
    
    // Verify password (use credentials directly without storing)
    const isValidPassword = await bcrypt.compare(password + rows[0].salt, rows[0].master_password_hash);
    
    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Return actual user data from database
    const userData = {
      userId: user.user_id,
      firstName: user.first_name,
      lastName: user.last_name,
      username: user.username,
      email: user.email,
      accountStatus: user.account_status,
      twoFactorEnabled: user.two_factor_enabled,
      lastLogin: user.last_login_timestamp,
      role: user.role // Add role to user data
    };
    
    // Get user and role permissions
    const role = rows[0].role;
    
    const [rolePermissions] = await pool.execute(`
        SELECT p.name 
        FROM sa_role_permissions rp 
        JOIN sa_permissions p ON rp.permission_id = p.id 
        WHERE rp.role = ?
    `, [role]);

    const [userPermissions] = await pool.execute(`
        SELECT p.name 
        FROM sa_user_permissions up 
        JOIN sa_permissions p ON up.permission_id = p.id 
        WHERE up.user_id = ?
    `, [user.user_id]);

    // Combine both sets of permissions
    const allPermissions = [...rolePermissions, ...userPermissions];

    const tokenPayload = {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: allPermissions.map(p => p.name)
    };

    // Generate real JWT token with permissions
    const token = jwt.sign(
        tokenPayload,
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );

    // Set JWT token as HTTP-only cookie
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: userData,
        expiresIn: 3600
      }
    });
    
  } catch (error) {
    handleError(error, res, 'login', 500, 'Login error');
  }
};

// Simple verify function
const verifyTokenEndpoint = (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      userId: req.user.userId,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    }
  });
};

// Simple password reset request
const passwordResetRequest = (req, res) => {
  const { email } = req.body;
  
  res.json({
    success: true,
    message: 'Password reset request received (mock response)',
    data: {
      email: email,
      securityQuestion1: 'What is your favorite color?',
      securityQuestion2: 'What city were you born in?'
    }
  });
};

// Simple password reset
const passwordReset = (req, res) => {
  res.json({
    success: true,
    message: 'Password reset successful (mock response)'
  });
};

// Simple logout
const logout = (req, res) => {
  // Clear the HTTP-only cookie
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  res.json({
    success: true,
    message: 'Logout successful'
  });
};

// Refresh token
const refreshToken = async (req, res) => {
  try {
    const user = req.user;
    // Get user and role permissions
    const rolePermissions = await db.query(`
        SELECT p.name 
        FROM sa_role_permissions rp 
        JOIN sa_permissions p ON rp.permission_id = p.id 
        WHERE rp.role = ?
    `, [user.role]);

    const userPermissions = await db.query(`
        SELECT p.name 
        FROM sa_user_permissions up 
        JOIN sa_permissions p ON up.permission_id = p.id 
        WHERE up.user_id = ?
    `, [user.userId]);

    // Combine both sets of permissions
    const allPermissions = [...rolePermissions, ...userPermissions];

    const newToken = jwt.sign(
      {
        userId: user.userId,
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: allPermissions.map(p => p.name)
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // Set new JWT token as HTTP-only cookie
    res.cookie('authToken', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        expiresIn: 3600
      }
    });
  } catch (error) {
    handleError(error, res, 'refresh token');
  }
};

const verifyToken = async (token, userId) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return {
      userId: decoded.userId,
      username: decoded.username,
      email: decoded.email,
      role: decoded.role,
      permissions: decoded.permissions || [],
      version: 1
    };
  } catch (error) {
    const errorMessage = error && error.message ? error.message : 'Unknown error';
    console.error('Token decode error:', errorMessage);
    throw new Error('Invalid or expired token');
  }
};

// Check if email exists
const checkEmail = async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    const query = 'SELECT COUNT(*) as count FROM sa_users WHERE email = ?';
    const [rows] = await pool.execute(query, [email]);
    
    res.json({
      success: true,
      exists: rows[0].count > 0
    });
    
  } catch (error) {
    handleError(error, res, 'check email');
  }
};

// Create new user from IODD registration
const register = async (req, res) => {
  try {
    // Validate API key from header
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.FVARS.SECURE_API_SECRET) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    // Extract request data
    const {
      firstName,
      lastName,
      email,
      username,
      password,
      securityQuestion1,
      securityAnswer1,
      securityQuestion2,
      securityAnswer2,
      appKey,
      userRole
    } = req.body;

    // Validate app key
    if (appKey !== process.FVARS.IODD_APP_KEY) {
      return res.status(403).json({ success: false, message: 'Invalid app key' });
    }

    // Validate required fields
    if (!firstName || !lastName || !email || !username || !password) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    // Check if user already exists
    const checkQuery = 'SELECT user_id FROM sa_users WHERE email = ? OR username = ?';
    const [existing] = await pool.execute(checkQuery, [email, username]);
    
    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: 'User already exists' });
    }

    // Generate salt
    const salt = await bcrypt.genSalt(10);
    
    // Hash the already-hashed password with salt for bcrypt storage
    const passwordHash = await bcrypt.hash(password + salt, 10);
    const answer1Hash = securityAnswer1 ? await bcrypt.hash(securityAnswer1 + salt, 10) : null;
    const answer2Hash = securityAnswer2 ? await bcrypt.hash(securityAnswer2 + salt, 10) : null;

    // Create user account
    const insertQuery = `
      INSERT INTO sa_users (
        first_name, last_name, username, email, account_status,
        master_password_hash, salt, security_question_1, security_question_2,
        security_answer_1_hash, security_answer_2_hash, two_factor_secret,
        jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, role, created_at
      ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, 0, 1, 1, 60, 'User', NOW())
    `;
    
    const [result] = await pool.execute(insertQuery, [
      firstName,
      lastName,
      username,
      email,
      passwordHash,
      salt,
      securityQuestion1,
      securityQuestion2,
      answer1Hash,
      answer2Hash
    ]);

    const userId = result.insertId;

    // Get application_id from app_key
    const appQuery = 'SELECT application_id FROM sa_applications WHERE app_key = ?';
    const [appRows] = await pool.execute(appQuery, [appKey]);
    
    if (appRows.length > 0) {
      // Link user to IODD app
      const linkQuery = `
        INSERT INTO sa_app_user (application_id, user_id, status, track_user, app_role, created_at)
        VALUES (?, ?, 'Active', 'No', ?, NOW())
      `;
      await pool.execute(linkQuery, [appRows[0].application_id, userId, userRole || 'Member']);
    }

    res.json({
      success: true,
      message: 'User created successfully',
      userId: userId
    });

  } catch (error) {
    handleError(error, res, 'register user', 500, 'Registration failed');
  }
};

// Create new user
const createUser = async (req, res) => {
  try {
    // Validate API key from header
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.FVARS.API_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Validate app key from request body
    const { appKey } = req.body;
    if (appKey !== process.FVARS.IODD_APP_KEY) {
      return res.status(403).json({ error: 'Invalid app key' });
    }

    const {
      first_name,
      last_name,
      email,
      account_status,
      master_password_hash,
      security_question_1,
      security_question_2,
      security_answer_1_hash,
      security_answer_2_hash,
      two_factor_secret,
      jwt_secret_version,
      refresh_token_rotation_enabled,
      token_expiration_minutes,
      role
    } = req.body;
    
    // Generate username from email
    const username = email.split('@')[0];
    
    // Generate salt for password
    const salt = await bcrypt.genSalt(10);
    
    const insertParams = [
      first_name,
      last_name,
      username,
      email,
      account_status,
      master_password_hash,
      salt,
      security_question_1,
      security_question_2,
      security_answer_1_hash,
      security_answer_2_hash,
      two_factor_secret,
      jwt_secret_version,
      refresh_token_rotation_enabled,
      token_expiration_minutes,
      role
    ];
    
    const query = `
      INSERT INTO sa_users (
        first_name, last_name, username, email, account_status,
        master_password_hash, salt, security_question_1, security_question_2,
        security_answer_1_hash, security_answer_2_hash, two_factor_secret,
        jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, role, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;
    
    const [result] = await pool.execute(query, insertParams);
    
    // Generate JWT token for the new user
    const tokenPayload = {
      userId: result.insertId,
      username,
      email,
      role
    };
    
    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    res.json({
      success: true,
      message: 'User created successfully',
      data: {
        user_id: result.insertId,
        username,
        email,
        jwt_token: token
      }
    });
    
  } catch (error) {
    handleError(error, res, 'create user');
  }
};

// Create app-user relationship
const createAppUser = async (req, res) => {
  try {
    const { email, app_key, user_app_role, url_redirect } = req.body;
    
    // Get user_id from email
    const userQuery = 'SELECT user_id, first_name, last_name, username FROM sa_users WHERE email = ?';
    const [userRows] = await pool.execute(userQuery, [email]);
    
    if (userRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const user = userRows[0];
    
    // Get application data including URLs
    const appQuery = 'SELECT application_id, redirect_URL, failure_URL FROM sa_applications WHERE app_key = ?';
    const [appRows] = await pool.execute(appQuery, [app_key]);
    
    if (appRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }
    
    const app = appRows[0];
    
    // Create sa_app_user record
    const insertQuery = `
      INSERT INTO sa_app_user (application_id, user_id, status, track_user, app_role, created_at)
      VALUES (?, ?, 'Active', 'No', ?, NOW())
    `;
    
    await pool.execute(insertQuery, [app.application_id, user.user_id, user_app_role]);
    
    // Determine redirect URL based on url_redirect field
    let redirectUrl;
    if (url_redirect === 'redirect_URL') {
      redirectUrl = app.redirect_URL;
      // Build PKCE token for redirect_URL
      if (redirectUrl) {
        const userData = {
          user_id: user.user_id,
          username: user.username,
          email: email,
          first_name: user.first_name,
          last_name: user.last_name
        };
        const pkceToken = Buffer.from(JSON.stringify(userData)).toString('base64');
        redirectUrl += (redirectUrl.includes('?') ? '&' : '?') + `pkce=${pkceToken}`;
      }
    } else if (url_redirect === 'failure_URL') {
      redirectUrl = app.failure_URL;
    }
    
    res.json({
      success: true,
      message: 'App-user relationship created successfully',
      data: {
        redirect_url: redirectUrl
      }
    });
    
  } catch (error) {
    handleError(error, res, 'create app-user relationship');
  }
};

module.exports = {
  login,
  verifyTokenEndpoint,
  passwordResetRequest,
  passwordReset,
  logout,
  refreshToken,
  verifyToken,
  checkEmail,
  createUser,
  createAppUser,
  register
};
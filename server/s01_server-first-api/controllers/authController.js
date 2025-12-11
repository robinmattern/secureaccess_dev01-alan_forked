// Improved auth controller with proper response structure
const { pool } = require('../database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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
    console.log('========== DEBUG LOGIN START ==========');
    console.log('SQL Query:', query);
    console.log('Query parameters:', [username, username]);
    
    const [rows] = await pool.execute(query, [username, username]);
    console.log('Database result:', rows[0]);
    
    if (rows.length === 0) {
      console.log('No user found');
      console.log('========== DEBUG LOGIN END ==========');
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
        role: rows[0].role, // Explicitly include role
        master_password_hash: rows[0].master_password_hash,
        salt: rows[0].salt
    };
    
    console.log('Created user object:', user);
    console.log('Role from database:', rows[0].role);
    console.log('Raw database result:', rows[0]);
    console.log('Database columns:', Object.keys(rows[0]));
    console.log('Role field value:', rows[0].role);
    console.log('Role field type:', typeof rows[0].role);
    console.log('========== DEBUG LOGIN END ==========');
    
    // Debug user data
    console.log('User data debug:');
    console.log('Full user object:', user);
    console.log('User ID:', user.user_id);
    console.log('Username:', user.username);
    console.log('Role:', user.role);
    
    // Debug password verification
    console.log('Password verification debug:');
    console.log('Input password:', password);
    console.log('User salt:', user.salt);
    console.log('Stored hash:', user.master_password_hash);
    console.log('Combined for verification:', password + user.salt);
    
    // Verify password (match the format used in user creation)
    const isValidPassword = await bcrypt.compare(password + user.salt, user.master_password_hash);
    console.log('Password valid:', isValidPassword);
    
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
    console.log('========== DEBUG PERMISSIONS START ==========');
    
    // Ensure role is properly assigned from the database query
    const role = rows[0].role;
    console.log('User role from database:', role);
    
    const [rolePermissions] = await pool.execute(`
        SELECT p.name 
        FROM sa_role_permissions rp 
        JOIN sa_permissions p ON rp.permission_id = p.id 
        WHERE rp.role = ?
    `, [role]);
    
    console.log('Role permissions result:', rolePermissions);

    const [userPermissions] = await pool.execute(`
        SELECT p.name 
        FROM sa_user_permissions up 
        JOIN sa_permissions p ON up.permission_id = p.id 
        WHERE up.user_id = ?
    `, [user.user_id]);
    
    console.log('User permissions result:', userPermissions);
    console.log('========== DEBUG PERMISSIONS END ==========');

    // Combine both sets of permissions
    const allPermissions = [...rolePermissions, ...userPermissions];

    // Debug token data before generation
    console.log('========== DEBUG TOKEN GENERATION START ==========');
    const tokenPayload = {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role, // Use the role from user object
        permissions: allPermissions.map(p => p.name)
    };
    console.log('Token payload:', tokenPayload);
    console.log('Role value being added:', role);
    console.log('========== DEBUG TOKEN GENERATION END ==========');

    // Generate real JWT token with permissions
    const token = jwt.sign(
        tokenPayload,
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '1h' }
    );

    // Debug output
    console.log('User data for token:', {
        userId: user.user_id,
        username: user.username,
        role: user.role
    });
    
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
    res.status(500).json({
      success: false,
      message: 'Login error',
      error: error.message
    });
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
        role: user.role, // Add user's role
        permissions: allPermissions.map(p => p.name) // Add permissions to token
      },
      process.env.JWT_SECRET || 'your-secret-key',
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
    res.status(500).json({
      success: false,
      message: 'Token refresh failed',
      error: error.message
    });
  }
};

// Verify JWT token function for middleware
const verifyToken = async (token, userId) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    return {
      userId: decoded.userId,
      username: decoded.username,
      email: decoded.email,
      role: decoded.role,
      permissions: decoded.permissions || [],
      version: 1
    };
  } catch (error) {
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
    res.status(500).json({
      success: false,
      message: 'Error checking email',
      error: error.message
    });
  }
};

// Create new user
const createUser = async (req, res) => {
  try {
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
    
    const query = `
      INSERT INTO sa_users (
        first_name, last_name, username, email, account_status,
        master_password_hash, salt, security_question_1, security_question_2,
        security_answer_1_hash, security_answer_2_hash, two_factor_secret,
        jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, role, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;
    
    const [result] = await pool.execute(query, [
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
    ]);
    
    // Generate JWT token for the new user
    const tokenPayload = {
      userId: result.insertId,
      username: username,
      email: email,
      role: role
    };
    
    const token = jwt.sign(
      tokenPayload,
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1h' }
    );
    
    res.json({
      success: true,
      message: 'User created successfully',
      data: {
        user_id: result.insertId,
        username: username,
        email: email,
        jwt_token: token
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating user',
      error: error.message
    });
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
    res.status(500).json({
      success: false,
      message: 'Error creating app-user relationship',
      error: error.message
    });
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
  createAppUser
};
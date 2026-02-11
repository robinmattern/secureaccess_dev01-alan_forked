const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const {
  login,
  verifyTokenEndpoint,
  passwordResetRequest,
  passwordReset,
  logout,
  refreshToken,
  checkEmail,
  createUser,
  createAppUser,
  register
} = require('../controllers/authController');
const { 
  authenticateToken, 
  authRateLimit, 
  passwordResetRateLimit,
  createRateLimiter
} = require('../middleware/auth');

// Create a strict rate limiter for login
const strictAuthRateLimit = createRateLimiter(5, 15 * 60 * 1000, 'Too many login attempts');

// Temporary storage for authorization codes (use Redis or database in production)
const authCodes = new Map();
const MAX_AUTH_CODES = 10000;

// Clean up expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes.entries()) {
    if (now > data.expires_at) {
      authCodes.delete(code);
    }
  }
  if (authCodes.size > MAX_AUTH_CODES) {
    const entries = Array.from(authCodes.entries());
    entries.sort((a, b) => a[1].created_at - b[1].created_at);
    const toDelete = entries.slice(0, authCodes.size - MAX_AUTH_CODES);
    toDelete.forEach(([code]) => authCodes.delete(code));
  }
}, 5 * 60 * 1000);

// CSRF protection middleware
const csrfProtection = (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }
    
    const token = req.headers['x-requested-with'];
    if (!token || token !== 'XMLHttpRequest') {
        return res.status(403).json({
            success: false,
            message: 'Invalid request'
        });
    }
    
    next();
};

// Apply general rate limiting to auth routes
router.use(authRateLimit);

// POST /api/auth/login - User login (stricter rate limit)
router.post('/login', csrfProtection, strictAuthRateLimit, login);

// GET /api/auth/verify - Verify JWT token
router.get('/verify', authenticateToken, verifyTokenEndpoint);

// POST /api/auth/verify - Verify JWT token (alternative method)
router.post('/verify', csrfProtection, authenticateToken, verifyTokenEndpoint);

// POST /api/auth/password-reset-request - Request password reset (strict rate limit)
router.post('/password-reset-request', csrfProtection, passwordResetRateLimit, passwordResetRequest);

// POST /api/auth/password-reset - Reset password with security questions (strict rate limit)
router.post('/password-reset', csrfProtection, passwordResetRateLimit, passwordReset);

// POST /api/auth/logout - Logout user
router.post('/logout', csrfProtection, authenticateToken, logout);

// POST /api/auth/refresh - Refresh JWT token
router.post('/refresh', csrfProtection, authenticateToken, refreshToken);

// POST /api/auth/register - IODD member registration
router.post('/register', csrfProtection, register);

// POST /api/auth/check-email - Check if email exists
router.post('/check-email', csrfProtection, checkEmail);

// POST /api/auth/create-user - Create new user from PKCE token
router.post('/create-user', csrfProtection, createUser);

// POST /api/auth/create-app-user - Create app-user relationship
router.post('/create-app-user', csrfProtection, authenticateToken, createAppUser);

// POST /api/auth/verify-admin - Verify admin access
router.post('/verify-admin', csrfProtection, authenticateToken, (req, res) => {
  try {
    // Check if user has admin role
    if (!req.user || req.user.role !== 'Admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required',
        code: 'ADMIN_REQUIRED'
      });
    }
    
    res.json({
      success: true,
      message: 'Admin access verified',
      user: {
        userId: req.user.userId,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role
      }
    });
  } catch (error) {
    const errorMessage = error && error.message ? error.message : 'Unknown error';
    console.error('Admin verification error:', errorMessage);
    res.status(500).json({
      success: false,
      message: 'Admin verification failed'
    });
  }
});

// POST /api/auth/authorize - Generate PKCE authorization code
router.post('/authorize', csrfProtection, authenticateToken, async (req, res) => {
  try {
    const { 
      code_challenge, 
      code_challenge_method, 
      state, 
      redirect_uri 
    } = req.body;

    // Validate required PKCE parameters
    if (!code_challenge || code_challenge_method !== 'S256') {
      return res.status(400).json({
        success: false,
        message: 'Invalid PKCE parameters. code_challenge and code_challenge_method=S256 required'
      });
    }

    // Use only authenticated user data from JWT token (not from request body)
    const user_id = req.user.userId || req.user.user_id;
    const username = req.user.username;
    const email = req.user.email;
    const role = req.user.role;

    // Generate secure authorization code
    const authCode = crypto.randomBytes(32).toString('hex');
    
    // Store authorization data with 10-minute expiration
    authCodes.set(authCode, {
      user_id,
      username,
      email,
      role,
      code_challenge,
      code_challenge_method,
      state,
      redirect_uri,
      created_at: Date.now(),
      expires_at: Date.now() + (10 * 60 * 1000) // 10 minutes
    });

    console.log(`Authorization code generated for user: ${username}`);

    res.json({
      success: true,
      data: {
        code: authCode,
        expires_in: 600 // 10 minutes in seconds
      }
    });

  } catch (error) {
    const errorMessage = error && error.message ? error.message : 'Unknown error';
    console.error('Authorization error:', errorMessage);
    res.status(500).json({
      success: false,
      message: 'Failed to generate authorization code'
    });
  }
});

// POST /api/auth/token - Exchange authorization code for user data using PKCE
router.post('/token', csrfProtection, async (req, res) => {
  try {
    const { code, code_verifier, state } = req.body;

    // Validate required parameters
    if (!code || !code_verifier) {
      return res.status(400).json({
        success: false,
        message: 'Missing required parameters: code and code_verifier'
      });
    }

    // Retrieve stored authorization data
    const authData = authCodes.get(code);
    
    if (!authData) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired authorization code'
      });
    }

    // Check expiration
    if (Date.now() > authData.expires_at) {
      authCodes.delete(code);
      return res.status(400).json({
        success: false,
        message: 'Authorization code expired'
      });
    }

    // Verify state parameter if provided using constant-time comparison
    if (state && authData.state) {
      const stateMatch = crypto.timingSafeEqual(
        Buffer.from(state),
        Buffer.from(authData.state)
      );
      if (!stateMatch) {
        authCodes.delete(code);
        return res.status(400).json({
          success: false,
          message: 'Invalid state parameter'
        });
      }
    }

    // Validate code_verifier format
    if (!code_verifier || typeof code_verifier !== 'string' || code_verifier.length < 43 || code_verifier.length > 128) {
      return res.status(400).json({
        success: false,
        message: 'Invalid request parameters'
      });
    }

    // Verify PKCE code challenge using constant-time comparison
    const hash = crypto.createHash('sha256')
      .update(code_verifier)
      .digest('base64url');
    
    const expectedHash = Buffer.from(authData.code_challenge, 'base64url');
    const actualHash = Buffer.from(hash, 'base64url');
    
    if (!crypto.timingSafeEqual(expectedHash, actualHash)) {
      authCodes.delete(code);
      return res.status(400).json({
        success: false,
        message: 'Invalid request parameters'
      });
    }

    // PKCE verification successful - return user data
    const userData = {
      user_id: authData.user_id,
      username: authData.username,
      email: authData.email,
      role: authData.role
    };

    // Invalidate the authorization code (single use)
    authCodes.delete(code);

    console.log(`Authorization code exchanged successfully for user: ${userData.username}`);

    res.json({
      success: true,
      data: {
        user: userData,
        token_type: 'Bearer',
        scope: 'user_info'
      }
    });

  } catch (error) {
    const errorMessage = error && error.message ? error.message : 'Unknown error';
    console.error('Token exchange error:', errorMessage);
    res.status(500).json({
      success: false,
      message: 'Failed to exchange authorization code'
    });
  }
});

// GET /api/auth/codes - Debug endpoint to view active authorization codes (remove in production)
router.get('/codes', authenticateToken, (req, res) => {
  // Only allow admin users to view this debug info
  if (req.user.role !== 'Admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }

  const activeCodes = [];
  const now = Date.now();
  
  for (const [code, data] of authCodes.entries()) {
    activeCodes.push({
      code: code.substring(0, 8) + '...', // Partial code for security
      username: data.username,
      created_at: new Date(data.created_at).toISOString(),
      expires_at: new Date(data.expires_at).toISOString(),
      expired: now > data.expires_at
    });
  }

  res.json({
    success: true,
    data: {
      active_codes: activeCodes,
      total_count: authCodes.size
    }
  });
});

module.exports = router;
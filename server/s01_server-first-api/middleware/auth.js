const { verifyToken } = require('../controllers/authController');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    // Check for token in HTTP-only cookie first, then Authorization header
    let token = req.cookies?.authToken;
    
    if (!token) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }
    

    
    // Verify real JWT token
    const verifiedToken = await verifyToken(token);
    
    // Add user info to request
    req.user = {
      userId: verifiedToken.userId,
      username: verifiedToken.username,
      email: verifiedToken.email,
      role: verifiedToken.role,
      permissions: verifiedToken.permissions || [],
      version: verifiedToken.version
    };
    
    next();
  } catch (error) {
    const errorMessage = error && error.message ? error.message : 'Unknown error';
    console.error('Authentication error:', errorMessage);
    res.status(401).json({
      success: false,
      message: error.message || 'Invalid or expired token'
    });
  }
};

// Optional authentication middleware (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      try {
        const verifiedToken = await verifyToken(token);
        req.user = {
          userId: verifiedToken.userId,
          username: verifiedToken.username,
          email: verifiedToken.email,
          role: verifiedToken.role,
          permissions: verifiedToken.permissions || [],
          version: verifiedToken.version
        };
      } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.log('Optional auth failed:', errorMessage);
      }
    }
    
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

// Role-based authorization middleware
const authorize = (roles = []) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }
      
      // Check if user role is in allowed roles
      if (roles.length > 0 && !roles.includes(req.user.role)) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions'
        });
      }
      
      next();
    } catch (error) {
      const errorMessage = error && error.message ? error.message : 'Unknown error';
      console.error('Authorization error:', errorMessage);
      res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }
  };
};

// Rate limiting middleware using express-rate-limit
const createRateLimiter = (maxRequests = 100, windowMs = 15 * 60 * 1000, message = 'Too many requests') => {
  return rateLimit({
    windowMs,
    max: maxRequests,
    message: {
      success: false,
      message: `${message}. Please try again later.`,
      retryAfter: Math.ceil(windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        message: `${message}. Please try again later.`,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

// Pre-configured rate limiters
const generalRateLimit = createRateLimiter(100, 15 * 60 * 1000, 'Too many requests');
const authRateLimit = createRateLimiter(20, 15 * 60 * 1000, 'Too many authentication attempts');
const passwordResetRateLimit = createRateLimiter(3, 15 * 60 * 1000, 'Too many password reset requests');

module.exports = {
  authenticateToken,
  optionalAuth,
  authorize,
  createRateLimiter,
  generalRateLimit,
  authRateLimit,
  passwordResetRateLimit
};
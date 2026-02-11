const express = require('express');
const router = express.Router();
const {
  getAllUsers,
  getUserById,
  createUser,
  updateUser,
  updateLastLogin,
  deleteUser,
  getUserSecurity
} = require('../controllers/usersController');
const { getUserApplications } = require('../controllers/applicationsController');
const { authenticateToken, authorize, generalRateLimit } = require('../middleware/auth');

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

// Apply rate limiting to all user routes
router.use(generalRateLimit);

// GET /api/users - Get all users (requires authentication)
router.get('/', authenticateToken, getAllUsers);

// GET /api/users/me - Get own profile (requires authentication)
router.get('/me', authenticateToken, authorize(['Admin', 'User']), getUserById);

// PUT /api/users/me - Update own profile (requires authentication)
router.put('/me', csrfProtection, authenticateToken, authorize(['Admin', 'User']), updateUser);

// GET /api/users/applications - Get user applications (requires authentication)
router.get('/applications', authenticateToken, authorize(['Admin', 'User']), getUserApplications);

// GET /api/users/:id - Get user by ID (requires authentication)
router.get('/:id', authenticateToken, getUserById);

// GET /api/users/:id/security - Get user security info (requires authentication)
router.get('/:id/security', authenticateToken, getUserSecurity);

// POST /api/users - Create new user (public for registration)
router.post('/', csrfProtection, createUser);

// PUT /api/users/:id - Update user (requires authentication)
router.put('/:id', csrfProtection, authenticateToken, updateUser);



// PATCH /api/users/:id/login - Update last login timestamp (requires authentication)
router.patch('/:id/login', csrfProtection, authenticateToken, updateLastLogin);

// DELETE /api/users/:id - Delete user (requires authentication)
router.delete('/:id', csrfProtection, authenticateToken, deleteUser);

module.exports = router;
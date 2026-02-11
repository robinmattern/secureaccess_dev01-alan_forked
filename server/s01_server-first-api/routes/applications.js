const express = require('express');
const router = express.Router();
const {
  getApplicationById,
  getAllApplications,
  createApplication,
  getUserApplications
} = require('../controllers/applicationsController');
const { generalRateLimit, authenticateToken } = require('../middleware/auth');

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

// Apply rate limiting to application routes
router.use(generalRateLimit);

// GET /api/applications - Get all applications
router.get('/', getAllApplications);

// GET /api/applications/:id - Get application by ID
router.get('/:id', getApplicationById);

// POST /api/applications - Create new application
router.post('/', authenticateToken, csrfProtection, createApplication);

module.exports = router;
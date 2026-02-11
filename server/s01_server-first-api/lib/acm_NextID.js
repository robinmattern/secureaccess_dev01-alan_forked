require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');

/**
 * acm_NextID - Global ID generator function
 * Returns the next unique ID for a record in a table
 * 
 * @param {string} tableName - The name of the table to generate ID for
 * @returns {Promise<number>} - The next unique ID number
 */
async function acm_NextID(tableName) {
    if (!tableName || typeof tableName !== 'string') {
        throw new Error('Table name must be a non-empty string');
    }
    
    // Use environment variables for configuration with error handling
    let baseId, increment;
    try {
        baseId = parseInt(process.env.BASE_ID) || 1000;
        increment = parseInt(process.env.ID_INCREMENT) || 1;
        
        if (isNaN(baseId) || isNaN(increment)) {
            throw new Error('Invalid configuration values');
        }
    } catch (configError) {
        throw new Error(`Configuration error: ${configError.message}`);
    }
    
    try {
        // Simple ID generation using timestamp and random number
        const timestamp = Date.now();
        if (!timestamp || timestamp <= 0) {
            throw new Error('Invalid timestamp generated');
        }
        
        const randomValue = Math.random();
        if (isNaN(randomValue)) {
            throw new Error('Invalid random number generated');
        }
        
        const random = Math.floor(randomValue * 1000);
        // Use bitwise operations for better performance
        const nextId = baseId + (timestamp & 0x7FFFFFFF) + random;
        
        if (isNaN(nextId) || nextId <= 0) {
            throw new Error('Invalid ID calculated');
        }
        
        console.log(`Generated ID for table: ${tableName}, ID: ${nextId}`);
        
        return nextId;
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown ID generation error';
        throw new Error(`ID generation failed: ${errorMessage}`);
    }
}

// Make acm_NextID globally available
global.acm_NextID = acm_NextID;

// Express server setup
const app = express();
const PORT = process.env.PORT || 3000;

// Secure CORS configuration
const allowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:57301',
    'http://127.0.0.1:57301'
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'X-Requested-With']
}));
app.use(express.json());

// CSRF protection middleware
const csrfProtection = (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }
    
    const token = req.headers['x-requested-with'];
    const origin = req.headers['origin'];
    
    if (!token || token !== 'XMLHttpRequest') {
        return res.status(403).json({
            success: false,
            message: 'Invalid request'
        });
    }
    
    // Additional origin validation
    if (origin && !origin.match(/^https?:\/\/(localhost|127\.0\.0\.1)(:[0-9]+)?$/)) {
        return res.status(403).json({
            success: false,
            message: 'Invalid origin'
        });
    }
    
    next();
};

// API endpoint
app.post('/api/nextid', csrfProtection, async (req, res) => {
    try {
        const { tableName } = req.body;
        
        if (!tableName) {
            return res.status(400).json({ error: 'Table name is required' });
        }
        
        if (typeof tableName !== 'string') {
            return res.status(400).json({ error: 'Table name must be a string' });
        }
        
        const nextId = await acm_NextID(tableName);
        
        res.json({ 
            nextId: nextId,
            tableName: tableName,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('acm_NextID API Error:', error.message);
        res.status(500).json({ 
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Serve HTML page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'nextid_testpage.html'));
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        service: 'acm_NextID API',
        timestamp: new Date().toISOString()
    });
});

// Start server with error handling
try {
    const server = app.listen(PORT, () => {
        console.log(`acm_NextID Server running on port ${PORT}`);
        console.log(`acm_NextID function available globally as acm_NextID(tableName)`);
        console.log(`API endpoint: http://localhost:${PORT}/api/nextid`);
    });
    
    server.on('error', (error) => {
        const errorMessage = error && error.message ? error.message : 'Unknown server error';
        console.error('Server error:', errorMessage);
        process.exit(1);
    });
} catch (serverError) {
    const errorMessage = serverError && serverError.message ? serverError.message : 'Unknown startup error';
    console.error('Server startup failed:', errorMessage);
    process.exit(1);
}

// Export for use in other modules
module.exports = { acm_NextID };
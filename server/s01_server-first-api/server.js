const dotenv = require('dotenv')
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const crypto = require('crypto');
const validator = require('validator');

             require( "./_config.js" )                                                  // .(51013.01.3 RAM Load process.fvaR)
//    dotenv.config( { path:       `${ __dirname }/.env`) } );                          //#.(51013.01.3 RAM No workie in windows)
  var bOK =  dotenv.config( { path: path.join(__dirname, '.env') } );                   // .(51112.04.1 RAM Check if found .env)
  if (bOK.error) { console.warn('⚠️  Missing .env file, using defaults'); }             // .(51112.04.2 RAM Warn if not found)
                                                                                        // .(51013.04.13 RAM This works everywhere) 
const SECURE_API_URL   = process.FVARS.SERVER_API_URL || ''                             // .(51013.04.14 RAM not SECURE_PATH) 
      process.env.PORT = SECURE_API_URL.match(   /:([0-9]+)\/?/)?.slice(1,2)[0] ?? ''   // .(51013.04.15 RAM Define them here) 
      process.env.HOST = SECURE_API_URL.match(/(.+):[0-9]+\/?/ )?.slice(1,2)[0] ?? ''   // .(51013.04.16) 

const DB_LOCATION      = process.FVARS.DB_LOCATION || process.env.DB_LOCATION           // .(51112.04.3 RAM Check if DB_LOCATION has changed Beg) 
  if (DB_LOCATION     != process.env.DB_LOCATION) { 
      console.warn(`⚠️  DB_LOCATION mismatch: Switching to ${DB_LOCATION}.`);
  var bOK =  dotenv.config( { path: path.join( __dirname, `.env-${DB_LOCATION.toLowerCase()}` ), override: true } );                  
  if (bOK.error) { console.warn(`❌ Missing .env-${DB_LOCATION} file. Aborting`);      // .(51112.04.4 RAM Abort if not found)
      process.exit() 
      }  }                                                                              // .(51112.03.5 End)

// Debug environment variables
   console.log('🔧 Environment variables loaded:');
// console.log('   PORT:',       process.env.PORT);
// console.log('   HOST:',       process.env.HOST);
   console.log('   DB_HOST:',    process.env.DB_HOST);
   console.log('   DB_NAME:',    process.env.DB_NAME);
   console.log('   DB_USER:',    process.env.DB_USER);
   console.log('   JWT_SECRET:', process.env.JWT_SECRET ? '[SET]' : '[NOT SET]');

// CSRF Token generation
function generateSecureRandomToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Rate limiting store with cleanup
const loginAttempts = new Map();

// Cleanup expired rate limit entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of loginAttempts.entries()) {
        if (now > data.resetTime) {
            loginAttempts.delete(ip);
        }
    }
}, 5 * 60 * 1000);

// Rate limiting middleware
function rateLimitLogin(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxAttempts = 5;
    
    if (!loginAttempts.has(ip)) {
        loginAttempts.set(ip, { count: 0, resetTime: now + windowMs });
    }
    
    const attempts = loginAttempts.get(ip);
    
    if (now > attempts.resetTime) {
        attempts.count = 0;
        attempts.resetTime = now + windowMs;
    }
    
    if (attempts.count >= maxAttempts) {
        return res.status(429).json({
            success: false,
            message: 'Too many login attempts. Please try again later.'
        });
    }
    
    attempts.count++;
    next();
}

// Simple CSRF protection using custom header
function csrfCrossOrigin(req, res, next) {
    // Skip CSRF for GET requests
    if (req.method === 'GET') {
        return next();
    }
    
    // Check for custom header (prevents simple form-based attacks)
    const customHeader = req.headers['x-requested-with'];
    if (!customHeader || customHeader !== 'XMLHttpRequest') {
        console.log('❌ CSRF validation failed: Missing X-Requested-With header');
        // Avoid logging sensitive headers in production
        if (process.env.NODE_ENV !== 'production') {
            console.log('📋 Request headers:', req.headers);
        }
        return res.status(403).json({ error: 'Invalid request' });
    }
    
    console.log('✅ CSRF validation passed: X-Requested-With header present');
    next();
}

const app = express();

const PORT     =  process.env.PORT // || 3005;
const NODE_ENV =  process.env.NODE_ENV || 'development';
const HOST     =  NODE_ENV === 'production' ? process.env.PRODUCTION_HOST : process.env.HOST;    // .(51013.03.1 RAM PRODUCTION_HOST is not defined)  
//nst BASE_URL = `http${NODE_ENV === 'production' ? 's' : ''}://${HOST}:${PORT}`;                //#.(51013.03.2)
const BASE_URL = `${HOST}:${PORT}`;  
const SECURE_PATH = process.FVARS.SECURE_PATH || ''                                              // .(51013.04.17 RAM HOST includes http or https)

// JWT Secret - In production, use environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'SecureAccess-JWT-Secret-Key-2024!@#$%';
const JWT_EXPIRES_IN = '24h'; // Token expires in 24 hours
  var allowedOrigins_ = process.FVARS.CORS_ORIGINS || [ `${BASE_URL}`, SECURE_PATH ]                        // .(51210.01.1 RAM Add FVARS.CORS_ORIGINS) 
// Middleware
const allowedOrigins = (NODE_ENV === 'production') 
    ? [ `${HOST}:${PORT}`, `${HOST}`]
//  : [ `${BASE_URL}`, SECURE_PATH, 'http://127.0.0.1:49306', 'http://localhost:49306', 'http://127.0.0.1:5500', 'http://localhost:5500' ];  // .(51013.04.18 RAM Was: Server: SECURE_API_URL)
//  : [ `${BASE_URL}`, SECURE_PATH ];  
    :    allowedOrigins_;                                                                                   // .(51210.01.2) 
                                                               
    allowedOrigins.forEach( aHost => { 
        if (aHost.match(/localhost/) ) { allowedOrigins.push( aHost.replace( /localhost/, "127.0.0.1" ) ) } // .(51210.01.3 RAM Check both) 
        if (aHost.match(/127.0.0.1/) ) { allowedOrigins.push( aHost.replace( /127.0.0.1/, "localhost" ) ) } } )
    console.log( "   CORS.AllowedOrigins:\n    ", allowedOrigins.join('\n     '))

app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Access', 'X-Requested-With'],
    credentials: true
}));

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    next();
});
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Input sanitization middleware
function sanitizeInput(req, res, next) {
    if (req.body) {
        for (const key in req.body) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = validator.escape(req.body[key]);
            }
        }
    }
    next();
}

app.use(express.static(path.join(__dirname, '../../client/c01_client-first-app'))); // Serve client files

// CSRF Protection - configured for cross-origin
const csrfProtection = csrf({ 
    cookie: { 
        httpOnly: false,
        secure: false, 
        sameSite: 'lax'
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Request logging middleware
app.use((req, res, next) => {
    console.log(`🔍 ${new Date().toISOString()} - ${req.method} ${req.path}`);
    if (req.path.includes('/api/')) {
        console.log('🍪 All cookies in request:', req.cookies);
        console.log('📋 Raw cookie header:', req.headers.cookie);
    }
    next();
});

// JWT Token generation function
function generateToken(user) {
    const payload = {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        account_status: user.account_status
    };
    
    console.log('🎫 Generating JWT token for user:', user.username);
    console.log('🔑 JWT_SECRET length:', JWT_SECRET.length);
    console.log('🔑 JWT_SECRET preview:', JWT_SECRET.substring(0, 20) + '...');
    
    const token = jwt.sign(payload, JWT_SECRET, { 
        expiresIn: JWT_EXPIRES_IN,
        issuer: 'SecureAccess',
        audience: 'SecureAccess-Users'
    });
    
    console.log('✅ JWT token generated successfully');
    return token;
}

// JWT Token verification middleware
function verifyToken(req, res, next) {
    console.log('🔐 JWT Verification - Headers:', req.headers.authorization ? 'Bearer token present' : 'No Bearer token');
    console.log('🍪 JWT Verification - Cookies:', req.cookies?.authToken ? 'Auth cookie present' : 'No auth cookie');
    
    // Check for token in Authorization header first, then HTTP-only cookie
    let token = null;
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
        console.log('🎫 Using Bearer token from Authorization header');
    } else if (req.cookies?.authToken) {
        token = req.cookies.authToken;
        console.log('🎫 Using token from HTTP-only cookie');
    }

    if (!token) {
        console.log('❌ No token found in request');
        return res.status(401).json({
            success: false,
            message: 'Access token required',
            code: 'TOKEN_MISSING'
        });
    }

    try {
        console.log('🔍 Verifying JWT token...');
        console.log('🔑 Token preview:', token.substring(0, 50) + '...');
        console.log('🔑 JWT_SECRET being used:', JWT_SECRET.substring(0, 20) + '...');
        
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('✅ JWT decoded successfully:', { user_id: decoded.user_id, username: decoded.username, role: decoded.role, exp: decoded.exp, iat: decoded.iat });
        console.log('🕐 Current time:', Math.floor(Date.now() / 1000), 'Token exp:', decoded.exp);
        
        req.user = decoded;
        console.log('✅ JWT verification successful, user set:', req.user.user_id);
        next();
    } catch (error) {
        console.error('❌ JWT verification error:', error.message);
        console.error('❌ Full error:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid token: ' + error.message,
            code: 'TOKEN_INVALID'
        });
    }
}

// Admin role verification middleware
function requireAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required',
            code: 'AUTH_REQUIRED'
        });
    }
    
    if (req.user.role !== 'Admin') {
        console.log(`🚫 Access denied for user ${req.user.username} (role: ${req.user.role})`);
        return res.status(403).json({
            success: false,
            message: 'Admin access required',
            code: 'ADMIN_REQUIRED'
        });
    }
    
    console.log(`✅ Admin access granted for user ${req.user.username}`);
    next();
}

// Combined middleware for admin operations
const adminAccess = [verifyToken, requireAdmin];

// Database configuration from .env file
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT ||  3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'secureaccess2',
    timezone: 'Z'
};

// Database connection pool
let pool;

async function initDatabase() {
    try {
        pool = mysql.createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });
        
        // Test connection
        const connection = await pool.getConnection();
        console.log('✅ Connected to MySQL database successfully');
        connection.release();
        
        // Ensure sa_users table exists
        await ensureTableExists();
        
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown database connection error';
        console.error('❌ Database connection failed:', errorMessage);
        process.exit(1);
    }
}

// Ensure sa_users table exists with proper structure
async function ensureTableExists() {
    try {
        const createTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                first_name VARCHAR(50),
                last_name VARCHAR(50),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                master_password_hash VARCHAR(255) NOT NULL,
                account_status ENUM('Active', 'Inactive', 'Suspended') DEFAULT 'Active',
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                two_factor_secret VARCHAR(255),
                role ENUM('User', 'Admin') DEFAULT 'User',
                security_question_1 TEXT,
                security_answer_1_hash VARCHAR(255),
                security_question_2 TEXT,
                security_answer_2_hash VARCHAR(255),
                token_expiration_minutes INT DEFAULT 60,
                last_login_timestamp TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
        `;
        
        await pool.execute(createTableSQL);
        console.log('✅ sa_users table verified/created');
        
        // Create sa_applications table
        const createAppsTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_applications (
                application_id INT AUTO_INCREMENT PRIMARY KEY,
                application_name VARCHAR(100) NOT NULL,
                description TEXT,
                redirect_URL VARCHAR(255),
                failure_URL VARCHAR(255),
                app_key VARCHAR(100),
                security_roles VARCHAR(255),
                parm_email ENUM('Yes', 'No') DEFAULT 'No',
                parm_username ENUM('Yes', 'No') DEFAULT 'No',
                parm_PKCE ENUM('Yes', 'No') DEFAULT 'No',
                status ENUM('Active', 'Inactive') DEFAULT 'Inactive',
                date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
        `;
        
        await pool.execute(createAppsTableSQL);
        console.log('✅ sa_applications table verified/created');
        
        // Create sa_app_user table
        const createAppUserTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_app_user (
                app_user_id INT AUTO_INCREMENT PRIMARY KEY,
                application_id INT NOT NULL,
                user_id INT NOT NULL,
                app_role VARCHAR(50),
                status ENUM('Active', 'Inactive') DEFAULT 'Inactive',
                track_user ENUM('Yes', 'No') DEFAULT 'No',
                start_date DATE,
                end_date DATE,
                FOREIGN KEY (application_id) REFERENCES sa_applications(application_id),
                FOREIGN KEY (user_id) REFERENCES sa_users(user_id),
                UNIQUE KEY unique_app_user (application_id, user_id)
            );
        `;
        
        await pool.execute(createAppUserTableSQL);
        console.log('✅ sa_app_user table verified/created');
        
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown table creation error';
        console.error('❌ Error creating sa_users table:', errorMessage);
    }
}

// Utility function to hash passwords
async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

// Utility function to verify passwords
async function verifyPassword(password, hash) {
    // Handle case where hash is null/undefined/empty
    if (!hash || hash.trim() === '') {
        return false;
    }
    
    try {
        return await bcrypt.compare(password, hash);
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown password verification error';
        console.error('Password verification error:', errorMessage);
        return false;
    }
}

// Health check endpoint (no CSRF needed)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        database: 'connected'
    });
});

// Config endpoint to provide client configuration
app.get('/config', (req, res) => {
    res.json({
        port: PORT,
        host: HOST,
        environment: NODE_ENV,
        apiBaseUrl: `${BASE_URL}/api`
    });
});

// Applications endpoints
app.get('/api/applications', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT application_id, application_name, description,
                   redirect_URL, failure_URL, app_key, security_roles,
                   parm_email, parm_username, parm_PKCE, status
            FROM sa_applications 
            ORDER BY application_name
        `);
        
        res.json({
            success: true,
            data: rows
        });
    } catch (error) {
        console.error('Error fetching applications:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch applications',
            error: error.message
        });
    }
});

// Get application by app_key (public endpoint)
app.get('/api/applications/by-key/:app_key', async (req, res) => {
    try {
        const appKey = req.params.app_key;
        const [rows] = await pool.execute(`
            SELECT * FROM sa_applications WHERE app_key = ?
        `, [appKey]);
        
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Application not found'
            });
        }
        
        res.json({
            success: true,
            data: rows[0]
        });
    } catch (error) {
        console.error('Error fetching application by key:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch application',
            error: error.message
        });
    }
});

// Get individual application
app.get('/api/applications/:id', verifyToken, async (req, res) => {
    try {
        const appId = parseInt(req.params.id);
        const [rows] = await pool.execute(`
            SELECT * FROM sa_applications WHERE application_id = ?
        `, [appId]);
        
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Application not found'
            });
        }
        
        res.json({
            success: true,
            data: rows[0]
        });
    } catch (error) {
        console.error('Error fetching application:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch application',
            error: error.message
        });
    }
});

// Create new application
app.post('/api/applications', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const {
            application_name,
            description,
            redirect_URL,
            failure_URL,
            app_key,
            security_roles,
            parm_email = 'No',
            parm_username = 'No',
            parm_PKCE = 'No',
            status = 'Inactive'
        } = req.body;
        
        if (!application_name) {
            return res.status(400).json({
                success: false,
                message: 'Application name is required'
            });
        }
        
        const [result] = await pool.execute(`
            INSERT INTO sa_applications (
                application_name, description, redirect_URL, failure_URL, app_key, security_roles,
                parm_email, parm_username, parm_PKCE, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            application_name,
            description || null,
            redirect_URL || null,
            failure_URL || null,
            app_key || null,
            security_roles || null,
            parm_email,
            parm_username,
            parm_PKCE,
            status
        ]);
        
        res.status(201).json({
            success: true,
            message: 'Application created successfully',
            data: {
                application_id: result.insertId,
                application_name,
                description,
                redirect_URL,
                failure_URL,
                app_key,
                security_roles,
                parm_email,
                parm_username,
                parm_PKCE,
                status
            }
        });
    } catch (error) {
        console.error('Error creating application:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create application',
            error: error.message
        });
    }
});

// Update application
app.put('/api/applications/:id', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.id);
        const {
            application_name,
            description,
            redirect_URL,
            failure_URL,
            security_roles,
            parm_email,
            parm_username,
            parm_PKCE,
            status
        } = req.body;
        
        if (!application_name) {
            return res.status(400).json({
                success: false,
                message: 'Application name is required'
            });
        }
        
        const [result] = await pool.execute(`
            UPDATE sa_applications SET
                application_name = ?, description = ?, redirect_URL = ?, failure_URL = ?, security_roles = ?,
                parm_email = ?, parm_username = ?, parm_PKCE = ?, status = ?
            WHERE application_id = ?
        `, [
            application_name,
            description || null,
            redirect_URL || null,
            failure_URL || null,
            security_roles || null,
            parm_email || null,
            parm_username || null,
            parm_PKCE || null,
            status || null,
            applicationId
        ]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Application not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Application updated successfully'
        });
    } catch (error) {
        console.error('Error updating application:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update application',
            error: error.message
        });
    }
});

// Delete application
app.delete('/api/applications/:id', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.id);
        
        const [result] = await pool.execute(
            'DELETE FROM sa_applications WHERE application_id = ?',
            [applicationId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Application not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Application deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting application:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete application',
            error: error.message
        });
    }
});

// Get all users - PROTECTED WITH JWT
app.get('/api/users', adminAccess, async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT 
                user_id,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                role,
                token_expiration_minutes,
                last_login_timestamp,
                created_at,
                updated_at
            FROM sa_users 
            ORDER BY first_name, last_name
        `);
        
        res.json({
            success: true,
            data: rows
        });
        
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users',
            error: error.message
        });
    }
});

// Get specific user by ID - PROTECTED WITH JWT
app.get('/api/users/:id', verifyToken, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                user_id,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                two_factor_secret,
                role,
                security_question_1,
                security_answer_1_hash,
                security_question_2,
                security_answer_2_hash,
                token_expiration_minutes,
                last_login_timestamp,
                created_at,
                updated_at
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
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.error('Error fetching user:', errorMessage);
        if (!res.headersSent) {
            res.status(500).json({
                success: false,
                message: 'Failed to fetch user'
            });
        }
    }
});

// Get own profile - /me endpoint  
app.get('/api/users/me', verifyToken, async (req, res) => {
    try {
        console.log('👤 /users/me request from user:', req.user);
        
        if (!req.user) {
            console.log('❌ No user object in request');
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }
        
        const userId = req.user.user_id;
        console.log('🔍 Looking up user ID:', userId, 'Type:', typeof userId);
        
        if (!userId) {
            console.log('❌ No user ID in token:', req.user);
            return res.status(400).json({
                success: false,
                message: 'Invalid user data in token'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                user_id, first_name, last_name, username, email,
                account_status, last_login_timestamp, role,
                security_question_1, security_question_2, 
                two_factor_enabled, token_expiration_minutes, created_at, updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [parseInt(userId)]);
        
        if (rows.length === 0) {
            console.log('❌ User not found in database:', userId);
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        console.log('✅ User profile found:', rows[0].username);
        res.json({
            success: true,
            data: rows[0]
        });
        
    } catch (error) {
        console.error('❌ Error fetching user profile:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user profile',
            error: error.message
        });
    }
});

// Update own profile - /me endpoint
app.put('/api/users/me', csrfCrossOrigin, verifyToken, async (req, res) => {
    // Allow both Admin and User roles
    if (!req.user || !['Admin', 'User'].includes(req.user.role)) {
        return res.status(403).json({
            success: false,
            message: 'Access denied'
        });
    }
    
    try {
        const userId = req.user.user_id;
        
        const {
            first_name,
            last_name,
            username,
            email,
            password,
            security_question_1,
            security_answer_1,
            security_question_2,
            security_answer_2
        } = req.body;
        
        console.log('🔄 Profile update request for user ID:', userId);
        
        // Build dynamic update query
        const updates = [];
        const values = [];
        
        if (first_name !== undefined) {
            updates.push('first_name = ?');
            values.push(first_name);
        }
        if (last_name !== undefined) {
            updates.push('last_name = ?');
            values.push(last_name);
        }
        if (username !== undefined) {
            updates.push('username = ?');
            values.push(username);
        }
        if (email !== undefined) {
            updates.push('email = ?');
            values.push(email);
        }
        if (password !== undefined && password.trim() !== '') {
            console.log('🔒 Hashing new password...');
            const passwordHash = await hashPassword(password);
            updates.push('master_password_hash = ?');
            values.push(passwordHash);
        }
        if (security_question_1 !== undefined) {
            updates.push('security_question_1 = ?');
            values.push(security_question_1);
        }
        if (security_answer_1 !== undefined && security_answer_1.trim() !== '') {
            console.log('🔐 Hashing security_answer_1...');
            const hashedAnswer1 = await hashPassword(security_answer_1.trim());
            updates.push('security_answer_1_hash = ?');
            values.push(hashedAnswer1);
        }
        if (security_question_2 !== undefined) {
            updates.push('security_question_2 = ?');
            values.push(security_question_2);
        }
        if (security_answer_2 !== undefined && security_answer_2.trim() !== '') {
            console.log('🔐 Hashing security_answer_2...');
            const hashedAnswer2 = await hashPassword(security_answer_2.trim());
            updates.push('security_answer_2_hash = ?');
            values.push(hashedAnswer2);
        }
        
        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        // Add updated_at timestamp
        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(userId);
        
        // Validate updates array contains only safe column assignments
        const allowedColumns = ['first_name', 'last_name', 'username', 'email', 'master_password_hash', 'security_question_1', 'security_answer_1_hash', 'security_question_2', 'security_answer_2_hash', 'updated_at'];
        const safeUpdates = updates.filter(update => {
            const column = update.split(' = ')[0];
            return allowedColumns.includes(column);
        });
        
        const updateSQL = `UPDATE sa_users SET ${safeUpdates.join(', ')} WHERE user_id = ?`;
        
        const [updateResult] = await pool.execute(updateSQL, values);
        
        // Fetch updated user data
        const [updatedUser] = await pool.execute(`
            SELECT 
                user_id, first_name, last_name, username, email,
                security_question_1, security_question_2, updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: updatedUser[0]
        });
        
    } catch (error) {
        console.error('❌ Error updating profile:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile',
            error: error.message
        });
    }
});

// Create new user - PROTECTED WITH JWT
app.post('/api/users', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const {
            first_name,
            last_name,
            username,
            email,
            password,
            account_status = 'active',
            two_factor_enabled = false,
            role = 'User',
            security_question_1,
            security_answer_1,
            security_question_2,
            security_answer_2,
            token_expiration_minutes = 60
        } = req.body;
        
        // Validation
        if (!first_name || !last_name || !username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: first_name, last_name, username, email, password'
            });
        }
        
        // Validate email format
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }
        
        // Validate password strength
        if (!validator.isLength(password, { min: 8, max: 128 })) {
            return res.status(400).json({
                success: false,
                message: 'Password must be between 8 and 128 characters long'
            });
        }
        
        if (!validator.isStrongPassword(password, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        })) {
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            });
        }
        
        // Check if username or email already exists
        const [existingUsers] = await pool.execute(
            'SELECT user_id FROM sa_users WHERE username = ? OR email = ?',
            [username, email]
        );
        
        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Username or email already exists'
            });
        }
        
        // Hash password
        const passwordHash = await hashPassword(password);
        
        // Hash security answers if provided
        let hashedAnswer1 = null;
        let hashedAnswer2 = null;
        
        if (security_answer_1 && security_answer_1.trim() !== '') {
            hashedAnswer1 = await hashPassword(security_answer_1.trim());
        }
        
        if (security_answer_2 && security_answer_2.trim() !== '') {
            hashedAnswer2 = await hashPassword(security_answer_2.trim());
        }
        
        // Insert new user
        const [result] = await pool.execute(`
            INSERT INTO sa_users (
                first_name,
                last_name,
                username,
                email,
                master_password_hash,
                account_status,
                two_factor_enabled,
                role,
                security_question_1,
                security_answer_1_hash,
                security_question_2,
                security_answer_2_hash,
                token_expiration_minutes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            first_name,
            last_name,
            username,
            email,
            passwordHash,
            account_status,
            two_factor_enabled,
            role,
            security_question_1 || null,
            hashedAnswer1,
            security_question_2 || null,
            hashedAnswer2,
            token_expiration_minutes
        ]);
        
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: {
                user_id: result.insertId,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                token_expiration_minutes
            }
        });
        
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create user',
            error: error.message
        });
    }
});

// Update user - PROTECTED WITH JWT
app.put('/api/users/:id', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        // Check if user exists
        const [existingUser] = await pool.execute(
            'SELECT user_id FROM sa_users WHERE user_id = ?',
            [userId]
        );
        
        if (existingUser.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const {
            first_name,
            last_name,
            username,
            email,
            password,
            account_status,
            two_factor_enabled,
            role,
            security_question_1,
            security_answer_1,
            security_question_2,
            security_answer_2,
            token_expiration_minutes
        } = req.body;
        
        // Build dynamic update query
        const updates = [];
        const values = [];
        
        if (first_name !== undefined) {
            updates.push('first_name = ?');
            values.push(first_name);
        }
        if (last_name !== undefined) {
            updates.push('last_name = ?');
            values.push(last_name);
        }
        if (username !== undefined) {
            updates.push('username = ?');
            values.push(username);
        }
        if (email !== undefined) {
            updates.push('email = ?');
            values.push(email);
        }
        if (password !== undefined && password.trim() !== '') {
            const passwordHash = await hashPassword(password);
            updates.push('master_password_hash = ?');
            values.push(passwordHash);
        }
        if (account_status !== undefined) {
            updates.push('account_status = ?');
            values.push(account_status);
        }
        if (two_factor_enabled !== undefined) {
            updates.push('two_factor_enabled = ?');
            values.push(two_factor_enabled);
        }
        if (role !== undefined) {
            updates.push('role = ?');
            values.push(role);
        }
        if (security_question_1 !== undefined) {
            updates.push('security_question_1 = ?');
            values.push(security_question_1);
        }
        if (security_answer_1 !== undefined && security_answer_1.trim() !== '') {
            const hashedAnswer1 = await hashPassword(security_answer_1.trim());
            updates.push('security_answer_1_hash = ?');
            values.push(hashedAnswer1);
        }
        if (security_question_2 !== undefined) {
            updates.push('security_question_2 = ?');
            values.push(security_question_2);
        }
        if (security_answer_2 !== undefined && security_answer_2.trim() !== '') {
            const hashedAnswer2 = await hashPassword(security_answer_2.trim());
            updates.push('security_answer_2_hash = ?');
            values.push(hashedAnswer2);
        }
        if (token_expiration_minutes !== undefined) {
            updates.push('token_expiration_minutes = ?');
            values.push(token_expiration_minutes);
        }
        
        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        // Add updated_at timestamp
        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(userId);
        
        // Validate updates array contains only safe column assignments
        const allowedColumns = ['first_name', 'last_name', 'username', 'email', 'master_password_hash', 'account_status', 'two_factor_enabled', 'role', 'security_question_1', 'security_answer_1_hash', 'security_question_2', 'security_answer_2_hash', 'token_expiration_minutes', 'updated_at'];
        const safeUpdates = updates.filter(update => {
            const column = update.split(' = ')[0];
            return allowedColumns.includes(column);
        });
        
        const updateSQL = `UPDATE sa_users SET ${safeUpdates.join(', ')} WHERE user_id = ?`;
        
        const [updateResult] = await pool.execute(updateSQL, values);
        
        res.json({
            success: true,
            message: 'User updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user',
            error: error.message
        });
    }
});

// Delete user - PROTECTED WITH JWT
app.delete('/api/users/:id', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        // Check if user exists
        const [existingUser] = await pool.execute(
            'SELECT user_id, username FROM sa_users WHERE user_id = ?',
            [userId]
        );
        
        if (existingUser.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        // Delete the user
        await pool.execute('DELETE FROM sa_users WHERE user_id = ?', [userId]);
        
        res.json({
            success: true,
            message: `User ${existingUser[0].username} deleted successfully`
        });
        
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user',
            error: error.message
        });
    }
});

// Get users for specific application
app.get('/api/app-users/:applicationId', adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        
        const [rows] = await pool.execute(`
            SELECT au.*, u.first_name, u.last_name, u.username
            FROM sa_app_user au
            INNER JOIN sa_users u ON au.user_id = u.user_id
            WHERE au.application_id = ?
            ORDER BY u.first_name, u.last_name
        `, [applicationId]);
        
        res.json({
            success: true,
            data: rows
        });
    } catch (error) {
        console.error('Error fetching application users:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch application users',
            error: error.message
        });
    }
});

// Create app-user assignment
app.post('/api/app-users', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const {
            application_id,
            user_id,
            app_role,
            status = 'Inactive',
            track_user = 'No',
            start_date,
            end_date
        } = req.body;
        
        if (!application_id || !user_id) {
            return res.status(400).json({
                success: false,
                message: 'Application ID and User ID are required'
            });
        }
        
        const [result] = await pool.execute(`
            INSERT INTO sa_app_user (
                application_id, user_id, app_role, status, track_user, start_date, end_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [application_id, user_id, app_role, status, track_user, start_date || null, end_date || null]);
        
        res.status(201).json({
            success: true,
            message: 'User assignment created successfully',
            data: {
                app_user_id: result.insertId,
                application_id,
                user_id,
                app_role,
                status,
                track_user
            }
        });
    } catch (error) {
        console.error('Error creating app-user assignment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create user assignment',
            error: error.message
        });
    }
});

// Update app-user assignment
app.put('/api/app-users/:applicationId/:userId', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        const userId = parseInt(req.params.userId);
        const {
            app_role,
            status,
            track_user,
            start_date,
            end_date
        } = req.body;
        
        const [result] = await pool.execute(`
            UPDATE sa_app_user SET
                app_role = ?, status = ?, track_user = ?, start_date = ?, end_date = ?
            WHERE application_id = ? AND user_id = ?
        `, [app_role, status, track_user, start_date || null, end_date || null, applicationId, userId]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'User assignment not found'
            });
        }
        
        res.json({
            success: true,
            message: 'User assignment updated successfully'
        });
    } catch (error) {
        console.error('Error updating app-user assignment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user assignment',
            error: error.message
        });
    }
});

// Delete app-user assignment
app.delete('/api/app-users/:applicationId/:userId', csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        const userId = parseInt(req.params.userId);
        
        const [result] = await pool.execute(
            'DELETE FROM sa_app_user WHERE application_id = ? AND user_id = ?',
            [applicationId, userId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'User assignment not found'
            });
        }
        
        res.json({
            success: true,
            message: 'User assignment deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting app-user assignment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user assignment',
            error: error.message
        });
    }
});

// User applications endpoint
app.get('/api/user-applications', verifyToken, async (req, res) => {
    try {
        const userId = req.user.user_id;
        const [rows] = await pool.execute(`
            SELECT a.application_id, a.application_name, a.description
            FROM sa_applications a
            INNER JOIN sa_app_user au ON a.application_id = au.application_id
            WHERE au.user_id = ?
            ORDER BY a.application_name
        `, [userId]);
        
        res.json({
            success: true,
            data: rows
        });
    } catch (error) {
        console.error('Error fetching user applications:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user applications',
            error: error.message
        });
    }
});

// Login endpoint - UPDATED TO GENERATE JWT TOKENS
app.post('/api/auth/login', rateLimitLogin, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log(`🔍 Login attempt for username: ${username}`);
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }
        
        // Find user by username or email
        const [users] = await pool.execute(
            'SELECT user_id, first_name, last_name, username, email, account_status, two_factor_enabled, last_login_timestamp, master_password_hash, role FROM sa_users WHERE username = ? OR email = ?',
            [username, username]
        );
        
        if (users.length === 0) {
            console.log(`❌ User not found: ${username}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        const user = users[0];
        console.log(`✅ User found: ${user.username}`);
        
        // Verify password
        const passwordValid = await bcrypt.compare(password, user.master_password_hash);
        
        if (!passwordValid) {
            console.log(`❌ Invalid password for user: ${username}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        // Reset rate limit on successful login
        const ip = req.ip || req.connection.remoteAddress;
        if (loginAttempts.has(ip)) {
            loginAttempts.delete(ip);
        }
        
        // Check account status (case insensitive)
        if (user.account_status.toLowerCase() !== 'active') {
            console.log(`❌ Account not active: ${user.account_status}`);
            return res.status(403).json({
                success: false,
                message: 'Account is disabled'
            });
        }
        
        // Generate JWT token
        const token = generateToken(user);
        console.log(`🎫 Generated JWT token for user: ${username}`);
        
        // Update last login timestamp
        await pool.execute(
            'UPDATE sa_users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
            [user.user_id]
        );
        
        console.log(`✅ Login successful for user: ${username} (role: ${user.role})`);
        
        // Set JWT token as HTTP-only cookie
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        // Return user info (excluding sensitive data)
        const { master_password_hash, security_answer_1_hash, security_answer_2_hash, two_factor_secret, ...userInfo } = user;
        
        res.json({
            success: true,
            message: 'Login successful',
            data: {
                user: userInfo,
                token: token,
                sessionId: token
            }
        });
        
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    }
});

// Get computer information
app.get('/api/computer-info', verifyToken, async (req, res) => {
    const { exec } = require('child_process');
    const os = require('os');
    
    try {
        // Get local IP address
        const networkInterfaces = os.networkInterfaces();
        let localIP = 'Unknown';
        
        for (const interfaceName in networkInterfaces) {
            const interfaces = networkInterfaces[interfaceName];
            for (const iface of interfaces) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    localIP = iface.address;
                    break;
                }
            }
            if (localIP !== 'Unknown') break;
        }
        
        const computerInfo = {
            computer_name: os.hostname(),
            computer_ip: localIP,
            computer_MAC: 'Unknown'
        };
        
        // Get MAC address based on OS
        const isWindows = os.platform() === 'win32';
        const command = isWindows ? 'getmac /fo csv /nh' : 'ifconfig | grep -o -E "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}" | head -1';
        
        exec(command, (error, stdout) => {
            if (!error && stdout) {
                if (isWindows) {
                    const mac = stdout.split(',')[0].replace(/"/g, '').trim();
                    computerInfo.computer_MAC = mac;
                } else {
                    computerInfo.computer_MAC = stdout.trim();
                }
            }
            
            res.json({
                success: true,
                data: computerInfo
            });
        });
    } catch (error) {
        res.json({
            success: true,
            data: {
                computer_name: os.hostname(),
                computer_ip: 'Unknown',
                computer_MAC: 'Unknown'
            }
        });
    }
});

// Track application usage
app.post('/api/track-user', csrfCrossOrigin, verifyToken, async (req, res) => {
    try {
        const userId = req.user.user_id;
        const { application_id, computer_name, computer_MAC, computer_ip } = req.body;
        
        if (!application_id) {
            return res.status(400).json({
                success: false,
                message: 'application_id is required'
            });
        }
        
        // Create tracking table if it doesn't exist
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS sa_tracking_user (
                tracking_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                application_id INT NOT NULL,
                event_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                computer_name VARCHAR(255),
                computer_MAC VARCHAR(255),
                computer_ip VARCHAR(255),
                FOREIGN KEY (user_id) REFERENCES sa_users(user_id),
                FOREIGN KEY (application_id) REFERENCES sa_applications(application_id)
            )
        `);
        
        await pool.execute(`
            INSERT INTO sa_tracking_user (user_id, application_id, event_date, computer_name, computer_MAC, computer_ip)
            VALUES (?, ?, NOW(), ?, ?, ?)
        `, [userId, application_id, computer_name || 'Unknown', computer_MAC || 'Unknown', computer_ip || 'Unknown']);
        
        res.json({
            success: true,
            message: 'Application usage tracked'
        });
    } catch (error) {
        console.error('Error tracking application usage:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to track application usage',
            error: error.message
        });
    }
});

// Get security questions - PUBLIC ACCESS (no CSRF protection)
app.post('/api/auth/security-questions', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username || username.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Username is required'
            });
        }
        
        const [users] = await pool.execute(
            'SELECT security_question_1, security_question_2 FROM sa_users WHERE username = ? OR email = ?',
            [username.trim(), username.trim()]
        );
        
        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const user = users[0];
        res.json({
            success: true,
            data: {
                security_question_1: user.security_question_1,
                security_question_2: user.security_question_2
            }
        });
        
    } catch (error) {
        console.error('Error fetching security questions:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch security questions'
        });
    }
});

// Verify security answer - PUBLIC ACCESS (no CSRF protection)
app.post('/api/auth/verify-security-answer', async (req, res) => {
    try {
        const { username, questionNumber, answer } = req.body;
        
        if (!username || !questionNumber || !answer) {
            return res.status(400).json({
                success: false,
                message: 'Username, question number, and answer are required'
            });
        }
        
        const answerField = questionNumber === 1 ? 'security_answer_1_hash' : 'security_answer_2_hash';
        
        const answerColumn = questionNumber === 1 ? 'security_answer_1_hash' : 'security_answer_2_hash';
        const [users] = await pool.execute(
            `SELECT ${answerColumn} FROM sa_users WHERE username = ? OR email = ?`,
            [username.trim(), username.trim()]
        );
        
        if (users.length === 0) {
            return res.json({ success: false });
        }
        
        const user = users[0];
        const storedHash = user[answerField];
        
        if (!storedHash) {
            return res.json({ success: false });
        }
        
        const isValid = await verifyPassword(answer.trim(), storedHash);
        res.json({ success: isValid });
        
    } catch (error) {
        console.error('Error verifying security answer:', error);
        res.json({ success: false });
    }
});

// Verify JWT token endpoint - for checking if user is authenticated
app.get('/api/auth/verify', verifyToken, async (req, res) => {
    try {
        // If we reach here, the JWT token is valid (verifyToken middleware passed)
        res.json({
            success: true,
            data: {
                user_id: req.user.user_id,
                username: req.user.username,
                email: req.user.email,
                role: req.user.role,
                account_status: req.user.account_status
            }
        });
    } catch (error) {
        console.error('Error in auth verify:', error);
        res.status(500).json({
            success: false,
            message: 'Authentication verification failed'
        });
    }
});

// Auth routes are handled directly in server.js

// Check if email exists
app.post('/api/auth/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        const [rows] = await pool.execute('SELECT COUNT(*) as count FROM sa_users WHERE email = ?', [email]);
        res.json({ success: true, exists: rows[0].count > 0 });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error checking email' });
    }
});

// Create new user from PKCE token
app.post('/api/auth/create-user', async (req, res) => {
    try {
        const { first_name, last_name, email, account_status, master_password_hash, security_question_1, security_question_2, security_answer_1_hash, security_answer_2_hash, role } = req.body;
        
        const username = email.split('@')[0];
        const hashedPassword = await hashPassword(master_password_hash);
        
        const [result] = await pool.execute(`
            INSERT INTO sa_users (first_name, last_name, username, email, account_status, master_password_hash, security_question_1, security_question_2, security_answer_1_hash, security_answer_2_hash, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [first_name, last_name, username, email, account_status, hashedPassword, security_question_1, security_question_2, security_answer_1_hash, security_answer_2_hash, role]);
        
        // Explicitly update account_status to ensure it's set to active
        await pool.execute('UPDATE sa_users SET account_status = ? WHERE user_id = ?', ['active', result.insertId]);
        
        const token = jwt.sign({ userId: result.insertId, username, email, role }, JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ success: true, message: 'User created successfully', data: { user_id: result.insertId, username, email, jwt_token: token } });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ success: false, message: 'Error creating user', error: error.message });
    }
});

// Create app-user relationship
app.post('/api/auth/create-app-user', verifyToken, async (req, res) => {
    try {
        console.log('Create app-user request:', req.body);
        const { email, app_key, user_app_role, url_redirect } = req.body;
        
        const [userRows] = await pool.execute('SELECT user_id, first_name, last_name, username FROM sa_users WHERE email = ?', [email]);
        if (userRows.length === 0) {
            console.log('User not found for email:', email);
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const user = userRows[0];
        console.log('Found user:', user);
        
        const [appRows] = await pool.execute('SELECT application_id, redirect_URL, failure_URL FROM sa_applications WHERE app_key = ?', [app_key]);
        if (appRows.length === 0) {
            console.log('Application not found for app_key:', app_key);
            return res.status(404).json({ success: false, message: 'Application not found' });
        }
        
        const app = appRows[0];
        console.log('Found application:', app);
        
        console.log('Inserting sa_app_user record:', { application_id: app.application_id, user_id: user.user_id });
        await pool.execute('INSERT INTO sa_app_user (application_id, user_id, status, track_user, app_role) VALUES (?, ?, "Active", "No", "Member")', [app.application_id, user.user_id]);
        console.log('sa_app_user record created successfully');
        
        let redirectUrl = url_redirect === 'redirect_URL' ? app.redirect_URL : app.failure_URL;
        if (url_redirect === 'redirect_URL' && redirectUrl) {
            const userData = { user_id: user.user_id, username: user.username, email, first_name: user.first_name, last_name: user.last_name };
            const pkceToken = Buffer.from(JSON.stringify(userData)).toString('base64');
            redirectUrl += (redirectUrl.includes('?') ? '&' : '?') + `pkce=${pkceToken}`;
        }
        
        res.json({ success: true, message: 'App-user relationship created successfully', data: { redirect_url: redirectUrl } });
    } catch (error) {
        console.error('Create app-user error:', error);
        res.status(500).json({ success: false, message: 'Error creating app-user relationship', error: error.message });
    }
});

// Update password after security verification - PUBLIC ACCESS (no CSRF protection)
app.post('/api/auth/update-password', async (req, res) => {
    try {
        const { username, newPassword } = req.body;
        
        if (!username || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Username and new password are required'
            });
        }
        
        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }
        
        const passwordHash = await hashPassword(newPassword);
        
        const [result] = await pool.execute(
            'UPDATE sa_users SET master_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ? OR email = ?',
            [passwordHash, username.trim(), username.trim()]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        console.log(`Password updated for user: ${username}`);
        
        res.json({
            success: true,
            message: 'Password updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update password'
        });
    }
});

function listRoutes() {
    console.log('\n    === Registered Routes ===');
    app._router.stack.forEach((middleware, index) => {
        if (middleware.route) {
            const methods = Object.keys(middleware.route.methods).join(', ').toUpperCase();
            console.log(`    ${methods.padEnd(6)} ${middleware.route.path}`);
        }
    });
    console.log('    ========================\n');
}

// Start server
async function startServer() {
    try {
        await initDatabase();

        listRoutes()

        server = app.listen(PORT, () => {
            console.log(`📊 Admin page:   ${SECURE_PATH}/admin-users.html`);
            console.log(`📊 Login page:   ${SECURE_PATH}/index.html`);
            console.log(`🏥 Health check: ${BASE_URL}/health`);
            console.log(`🌍 Environment:  ${NODE_ENV}`);
            console.log(`🔐 JWT Security: ENABLED`);
            
            console.log(`\n🚀 Server is running at: ${BASE_URL}`);
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
let server;

async function gracefulShutdown(signal) {
    console.log(`\n🛑 Received ${signal}. Shutting down server...`);
    
    if (server) {
        server.close(() => {
            console.log('✅ HTTP server closed');
        });
    }
    
    if (pool) {
        await pool.end();
        console.log('✅ Database connections closed');
    }
    
    process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Windows specific signals
if (process.platform === 'win32') {
    process.on('SIGBREAK', () => gracefulShutdown('SIGBREAK'));
}

// Start the server
startServer();
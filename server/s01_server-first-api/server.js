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
const security = require('./middleware/security');
const redis = require('redis');
const { handleError, safeJsonParse } = require('./utils/errorHandler');
const fs = require('fs').promises;
const nodemailer = require('nodemailer');

             require( "./_config.js" )                                                  // .(51013.01.3 RAM Load process.fvaR)
//    dotenv.config( { path:       `${ __dirname }/.env`) } );                          //#.(51013.01.3 RAM No workie in windows)
  var bOK =  dotenv.config( { path: path.join(__dirname, '.env') } );                   // .(51112.04.1 RAM Check if found .env)
  if (bOK.error) { console.error('❌ Missing .env file, using defaults'); }             // .(51112.04.2 RAM Warn if not found)
                                                                                        // .(51013.04.13 RAM This works everywhere)
const SECURE_API_URL   = process.FVARS.SERVER_API_URL || ''                             // .(51013.04.14 RAM not SECURE_PATH)
      process.env.PORT = SECURE_API_URL.match(   /:([0-9]+)\/?/)?.slice(1,2)[0] || process.env.PORT || '3000'   // .(51013.04.15 RAM Define them here)
      process.env.HOST = SECURE_API_URL.match(/(.+):[0-9]+\/?/ )?.slice(1,2)[0] || process.env.HOST || 'http://localhost'   // .(51013.04.16)

const DB_LOCATION      = process.FVARS.DB_LOCATION || process.env.DB_LOCATION           // .(51112.04.3 RAM Check if DB_LOCATION has changed Beg)
  if (DB_LOCATION     != process.env.DB_LOCATION) {
      console.warn(`⚠️ DB_LOCATION mismatch: Switching to ${DB_LOCATION}.`);
  var bOK =  dotenv.config( { path: path.join( __dirname, `.env-${DB_LOCATION.toLowerCase()}` ), override: true } );
  if (bOK.error) { console.warn(`⚠️ Missing .env-${DB_LOCATION} file. Aborting`);        // .(51112.04.4 RAM Abort if not found)
      process.exit()
      }  }                                                                              // .(51112.03.5 End)
   if (DB_LOCATION == "Remote") {
      process.env.PORT = process.FVARS.SERVER_PORT || process.env.PORT || '3000'                                      // .(51211.07.1 RAM Define them here) 
      process.env.HOST = process.FVARS.SECURE_HOST || process.env.HOST || 'http://localhost'                                      // .(51211.07.2) 
      console.log( `process.env: {` )
      console.log( `  "PORT":             "${process.env.PORT}"` )
      console.log( `  "HOST":             "${process.env.HOST}"` )
      console.log( `  }` )
      }

// Debug environment variables
    console.log('ℹ️  Environment variables loaded:');
//  console.log('   PORT:',       process.env.PORT);
//  console.log('   HOST:',       process.env.HOST);
    console.log('   DB_HOST:',    process.env.DB_HOST ? '[SET]' : '[NOT SET]');
    console.log('   DB_NAME:',    process.env.DB_NAME ? '[SET]' : '[NOT SET]');
    console.log('   DB_USER:',    process.env.DB_USER ? '[SET]' : '[NOT SET]');
    console.log('   JWT_SECRET:', process.env.JWT_SECRET ? '[SET]' : '[NOT SET]');


// CSRF Token generation
function generateSecureRandomToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Rate limiting store with cleanup
const loginAttempts = new Map();

// 2FA code store (in-memory, expires after 10 minutes)
const twoFactorCodes = new Map();

// 2FA attempt tracking (rate limiting)
const twoFactorAttempts = new Map();

// SMTP config cache (to avoid reading file on every 2FA request)
let smtpConfigCache = null;
let smtpConfigCacheTime = 0;
const SMTP_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Load SMTP configuration with caching
async function loadSmtpConfig() {
    const now = Date.now();
    if (smtpConfigCache && (now - smtpConfigCacheTime) < SMTP_CACHE_TTL) {
        return smtpConfigCache;
    }
    
    const smtpPath = path.join(__dirname, '.env.SMTP');
    const smtpContent = await fs.readFile(smtpPath, 'utf8');
    const lines = smtpContent.split('\n');
    const config = {};
    const maxLines = 50;
    const lineCount = Math.min(lines.length, maxLines);
    for (let i = 0; i < lineCount; i++) {
        const match = lines[i].match(/^([A-Z_]+)=(.+)$/);
        if (match) config[match[1]] = match[2].replace(/"/g, '');
    }
    
    smtpConfigCache = config;
    smtpConfigCacheTime = now;
    return config;
}

// Redis client for 2FA storage (with fallback to in-memory)
let redisClient = null;
let useRedis = false;

// Initialize Redis connection
async function initRedis() {
    if (process.env.REDIS_ENABLED === 'true') {
        try {
            const redisPort = parseInt(process.env.REDIS_PORT);
            if (isNaN(redisPort) || redisPort < 1 || redisPort > 65535) {
                throw new Error('Invalid Redis port');
            }
            redisClient = redis.createClient({
                socket: {
                    host: process.env.REDIS_HOST || 'localhost',
                    port: redisPort || 6379
                },
                password: process.env.REDIS_PASSWORD || undefined
            });
            
            redisClient.on('error', (err) => {
                const errorMessage = err && err.message ? err.message : 'Unknown Redis error';
                console.error('❌ Redis error:', errorMessage);
                useRedis = false;
            });
            
            await redisClient.connect();
            useRedis = true;
            console.log('✅ Redis connected - using Redis for 2FA storage');
        } catch (error) {
            const errorMessage = error && error.message ? error.message : 'Unknown error';
            console.warn('⚠️  Redis not available, using in-memory storage:', errorMessage);
            useRedis = false;
        }
    } else {
        console.log('ℹ️  Redis disabled - using in-memory storage for 2FA');
    }
}

// 2FA Storage Helper Functions
const twoFactorStorage = {
    async set(key, value, expiresInSeconds) {
        if (useRedis && redisClient) {
            try {
                await redisClient.setEx(`2fa:${key}`, expiresInSeconds, JSON.stringify(value));
            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Redis set error:', errorMessage);
                twoFactorCodes.set(key, { ...value, expiresAt: Date.now() + (expiresInSeconds * 1000) });
            }
        } else {
            twoFactorCodes.set(key, { ...value, expiresAt: Date.now() + (expiresInSeconds * 1000) });
        }
    },
    
    async get(key) {
        if (useRedis && redisClient) {
            try {
                const data = await redisClient.get(`2fa:${key}`);
                if (!data) return null;
                
                let parsed;
                try {
                    parsed = JSON.parse(data);
                } catch (e) {
                    const errorMessage = e && e.message ? e.message : 'Unknown error';
                    console.error('Invalid JSON in Redis data:', errorMessage);
                    return null;
                }
                
                if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                    console.error('Invalid data structure in Redis');
                    return null;
                }
                
                return parsed;
            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Redis get error:', errorMessage);
                return twoFactorCodes.get(key) || null;
            }
        } else {
            const data = twoFactorCodes.get(key);
            if (data && Date.now() > data.expiresAt) {
                twoFactorCodes.delete(key);
                return null;
            }
            return data || null;
        }
    },
    
    async delete(key) {
        if (useRedis && redisClient) {
            try {
                await redisClient.del(`2fa:${key}`);
            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Redis delete error:', errorMessage);
            }
        }
        twoFactorCodes.delete(key);
    }
};

// Generate backup codes (10 codes, 8 characters each)
function generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < 10; i++) {
        const code = crypto.randomBytes(4).toString('hex').toUpperCase();
        codes.push(code);
    }
    return codes;
}

// Hash backup codes for storage
async function hashBackupCodes(codes) {
    return await Promise.all(codes.map(code => hashPassword(code)));
}

// Verify backup code
async function verifyBackupCode(code, hashedCodes) {
    if (!hashedCodes || hashedCodes.length === 0) return { valid: false, remainingCodes: [] };
    
    for (let i = 0; i < hashedCodes.length; i++) {
        const isValid = await verifyPassword(code, hashedCodes[i]);
        if (isValid) {
            // Remove used code
            const remaining = [...hashedCodes];
            remaining.splice(i, 1);
            return { valid: true, remainingCodes: remaining };
        }
    }
    return { valid: false, remainingCodes: hashedCodes };
}

// Cleanup expired rate limit entries every 5 minutes
let cleanupInterval = null;

function startCleanup() {
    if (cleanupInterval) return;
    
    cleanupInterval = setInterval(() => {
        const now = Date.now();
        
        // Only process if there are entries
        if (loginAttempts.size > 0) {
            for (const [ip, data] of loginAttempts.entries()) {
                if (now > data.resetTime) {
                    loginAttempts.delete(ip);
                }
            }
        }
        
        // Cleanup expired 2FA codes (only for in-memory, Redis auto-expires)
        if (!useRedis && twoFactorCodes.size > 0) {
            for (const [key, data] of twoFactorCodes.entries()) {
                if (now > data.expiresAt) {
                    twoFactorCodes.delete(key);
                }
            }
        }
        
        // Cleanup expired 2FA attempts
        if (twoFactorAttempts.size > 0) {
            for (const [key, data] of twoFactorAttempts.entries()) {
                if (now > data.resetTime) {
                    twoFactorAttempts.delete(key);
                }
            }
        }
    }, 5 * 60 * 1000);
}

startCleanup();

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
    if (req.method === 'GET') {
        return next();
    }

    const customHeader = req.headers['x-requested-with'];
    const origin = req.headers['origin'];
    const referer = req.headers['referer'];
    
    if (!customHeader || customHeader !== 'XMLHttpRequest') {
        console.error('❌ CSRF validation failed: Missing X-Requested-With header');
        return res.status(403).json({ error: 'Invalid request' });
    }
    
    if (origin && !origin.startsWith(BASE_URL_PREFIX)) {
        console.error('❌ CSRF validation failed: Invalid origin', { origin, BASE_URL_PREFIX });
        return res.status(403).json({ error: 'Invalid request' });
    }
    
    if (referer && !referer.startsWith(BASE_URL_PREFIX)) {
        console.error('❌ CSRF validation failed: Invalid referer', { referer, BASE_URL_PREFIX });
        return res.status(403).json({ error: 'Invalid request' });
    }

    next();
}

const app = express();

const PORT        =  process.env.PORT // || 3005;
const NODE_ENV    =  process.env.NODE_ENV || 'development';
const HOST        =  process.env.HOST || (NODE_ENV === 'production' ? process.env.PRODUCTION_HOST : null) || 'http://localhost';
const BASE_URL    =  HOST.includes(':' + PORT) ? HOST : (HOST.match(/secureaccess/i) ? HOST : `${HOST}:${PORT}`);
const SECURE_PATH =  process.FVARS.SECURE_PATH || '';

// Cache BASE_URL prefix for CSRF validation
const BASE_URL_PREFIX = BASE_URL.split(':').slice(0, 2).join(':'); 

// JWT Secret - In production, use environment variable
const JWT_SECRET = process.env.JWT_SECRET || '';
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET not set in environment variables');
    process.exit(1);
}
const JWT_EXPIRES_IN = '24h'; // Token expires in 24 hours
  var allowedOrigins_ = process.FVARS.CORS_ORIGINS || [ `${BASE_URL}`, SECURE_PATH ]                        // .(51210.01.1 RAM Add FVARS.CORS_ORIGINS)
// Middleware
const allowedOrigins = allowedOrigins_;                                                                    // .(51210.01.2)

    allowedOrigins.forEach( aHost => {
        if (aHost.match(/localhost/) ) { allowedOrigins.push( aHost.replace( /localhost/, "127.0.0.1" ) ) } // .(51210.01.3 RAM Check both)
        if (aHost.match(/127.0.0.1/) ) { allowedOrigins.push( aHost.replace( /127.0.0.1/, "localhost" ) ) } } )
    console.log('ℹ️  CORS.AllowedOrigins:\n    ', allowedOrigins.join('\n     '))
    console.log( '' )

app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Access', 'X-Requested-With', 'X-CSRF-Token'],
    credentials: true
}));

// Security headers middleware
app.use(security.securityHeaders);
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Input sanitization middleware
app.use(security.sanitizeInputs);

app.use(express.static(path.join(__dirname, '../../client/c01_client-first-app'))); // Serve client files

// CSRF Protection - configured for localhost development
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'lax', // Use 'lax' for localhost (sameSite:'none' requires secure:true)
        path: '/'
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Request logging middleware
app.use((req, res, next) => {
    console.log(`ℹ️  ${new Date().toISOString()} - ${req.method} ${req.path}`);
    if (req.path.includes('/api/')) {
        const safeCookies = req.cookies ? Object.keys(req.cookies).join(', ') : 'none';
        console.log('ℹ️  Cookie keys in request:', safeCookies);
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

    const token = jwt.sign(payload, JWT_SECRET, {
        expiresIn: JWT_EXPIRES_IN,
        issuer: 'SecureAccess',
        audience: 'SecureAccess-Users'
    });

    security.auditLog('TOKEN_GENERATED', { user_id: user.user_id, username: user.username });
    return token;
}

// JWT Token verification middleware
function verifyToken(req, res, next) {
    console.log('ℹ️  JWT Verification - Headers:', req.headers.authorization ? 'Bearer token present' : 'No Bearer token');
    console.log('ℹ️  JWT Verification - Cookies:', req.cookies?.authToken ? 'Auth cookie present' : 'No auth cookie');

    // Check for token in Authorization header first, then HTTP-only cookie
    let token = null;
    const authHeader = req.headers.authorization;
    
    if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ') && authHeader.length < 2048) {
        token = authHeader.substring(7);
        console.log('ℹ️  Using Bearer token from Authorization header');
    } else if (req.cookies?.authToken) {
        token = req.cookies.authToken;
        console.log('ℹ️  Using token from HTTP-only cookie');
    }

    if (!token) {
        console.error('❌ No token found in request');
        return res.status(401).json({
            success: false,
            message: 'Access token required',
            code: 'TOKEN_MISSING'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        security.auditLog('TOKEN_VERIFIED', { user_id: decoded.user_id, username: decoded.username, role: decoded.role, ip: req.ip });

        req.user = decoded;
        next();
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        security.auditLog('TOKEN_VERIFICATION_FAILED', { error: errorMessage, ip: req.ip });
        return res.status(401).json({
            success: false,
            message: 'Invalid token',
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
        console.error(`❌ Access denied for user ${req.user.username} (role: ${req.user.role})`);
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
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'secureaccess2',
    timezone: 'Z'
};

// Validate required database credentials
if (!dbConfig.password) {
    console.error('❌ DB_PASSWORD not set in environment variables');
    process.exit(1);
}

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
                two_factor_method ENUM('email', 'sms', 'app') DEFAULT 'email',
                two_factor_email VARCHAR(100),
                two_factor_phone VARCHAR(20),
                two_factor_verified BOOLEAN DEFAULT FALSE,
                backup_codes TEXT,
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
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    return await bcrypt.hash(password, saltRounds);
}

// Utility function to verify passwords
async function verifyPassword(password, hash) {
    if (!password || typeof password !== 'string') {
        console.error('Password validation failed');
        return false;
    }
    
    if (!hash || typeof hash !== 'string' || hash.trim() === '') {
        console.error('Hash validation failed');
        return false;
    }

    try {
        return await bcrypt.compare(password, hash);
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.error('Verification error:', errorMessage);
        return false;
    }
}

// Health check endpoint (no CSRF needed) - moved after CORS middleware
// Config endpoint to provide client configuration

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
        handleError(error, res, 'fetch applications');
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
        handleError(error, res, 'fetch application by key', 500, 'Failed to fetch application');
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
        handleError(error, res, 'fetch application');
    }
});

// Create new application
app.post('/api/applications', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
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
        handleError(error, res, 'create application');
    }
});

// Update application
app.put('/api/applications/:id', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.id);
        let {
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
        } = req.body;

        // Helper function to decode HTML entities
        const decodeHtmlEntities = (str) => {
            if (!str) return str;
            return str
                .replace(/&#x2F;/g, '/')
                .replace(/&amp;/g, '&')
                .replace(/&lt;/g, '<')
                .replace(/&gt;/g, '>')
                .replace(/&quot;/g, '"')
                .replace(/&#39;/g, "'");
        };
        
        redirect_URL = decodeHtmlEntities(redirect_URL);
        failure_URL = decodeHtmlEntities(failure_URL);

        if (!application_name) {
            return res.status(400).json({
                success: false,
                message: 'Application name is required'
            });
        }

        const [result] = await pool.execute(`
            UPDATE sa_applications SET
                application_name = ?, description = ?, redirect_URL = ?, failure_URL = ?, app_key = ?, security_roles = ?,
                parm_email = ?, parm_username = ?, parm_PKCE = ?, status = ?
            WHERE application_id = ?
        `, [
            application_name,
            description ?? null,
            redirect_URL ?? null,
            failure_URL ?? null,
            app_key ?? null,
            security_roles ?? null,
            parm_email ?? null,
            parm_username ?? null,
            parm_PKCE ?? null,
            status ?? null,
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
        handleError(error, res, 'update application');
    }
});

// Delete application
app.delete('/api/applications/:id', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
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
        handleError(error, res, 'delete application');
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
                two_factor_method,
                two_factor_email,
                two_factor_phone,
                two_factor_verified,
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
        handleError(error, res, 'fetch users');
    }
});

// Get own profile - /me endpoint (MUST be before /:id route)
app.get('/api/users/me', verifyToken, async (req, res) => {
    try {
        console.log('ℹ️  /users/me request from user:', JSON.stringify(req.user));

        if (!req.user) {
            console.error('❌ No user object in request');
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        const userId = req.user.user_id;
        console.log('ℹ️  Looking up user ID:', userId, 'Type:', typeof userId, 'Full user object:', JSON.stringify(req.user));

        if (!userId) {
            console.error('❌ No user ID in token:', JSON.stringify(req.user));
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
                two_factor_enabled, two_factor_method, two_factor_email, two_factor_phone, two_factor_verified,
                token_expiration_minutes, created_at, updated_at
            FROM sa_users
            WHERE user_id = ?
        `, [parseInt(userId)]);

        if (rows.length === 0) {
            console.error('❌ User not found in database:', userId);
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        console.log('ℹ️  User profile found:', rows[0].username);
        res.json({
            success: true,
            data: rows[0]
        });

    } catch (error) {
        handleError(error, res, 'fetch user profile');
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
                two_factor_method,
                two_factor_email,
                two_factor_phone,
                two_factor_verified,
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
        handleError(error, res, 'fetch user');
    }
});

// MOVED ABOVE - Get own profile route must be before /:id route
/*
app.get('/api/users/me', verifyToken, async (req, res) => {
    try {
        console.log('ℹ️  /users/me request from user:', JSON.stringify(req.user));

        if (!req.user) {
            console.error('❌ No user object in request');
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        const userId = req.user.user_id;
        console.log('ℹ️  Looking up user ID:', userId, 'Type:', typeof userId, 'Full user object:', JSON.stringify(req.user));

        if (!userId) {
            console.error('❌ No user ID in token:', JSON.stringify(req.user));
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
                two_factor_enabled, two_factor_method, two_factor_email, two_factor_phone, two_factor_verified,
                token_expiration_minutes, created_at, updated_at
            FROM sa_users
            WHERE user_id = ?
        `, [parseInt(userId)]);

        if (rows.length === 0) {
            console.error('❌ User not found in database:', userId);
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        console.log('ℹ️  User profile found:', rows[0].username);
        res.json({
            success: true,
            data: rows[0]
        });

    } catch (error) {
        handleError(error, res, 'fetch user profile');
    }
});
*/

// Update own profile - /me endpoint
app.put('/api/users/me', csrfProtection, csrfCrossOrigin, verifyToken, async (req, res) => {
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

        console.log('ℹ️  Profile update request for user ID:', userId);

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
        if (password !== undefined && password !== null && password.trim() !== '') {
            console.log('ℹ️  Hashing new password...');
            const passwordHash = await hashPassword(password);
            updates.push('master_password_hash = ?');
            values.push(passwordHash);
        }
        if (security_question_1 !== undefined) {
            updates.push('security_question_1 = ?');
            values.push(security_question_1);
        }
        if (security_answer_1 !== undefined && security_answer_1.trim() !== '') {
            console.log('ℹ️  Hashing security_answer_1...');
            const hashedAnswer1 = await hashPassword(security_answer_1.trim());
            updates.push('security_answer_1_hash = ?');
            values.push(hashedAnswer1);
        }
        if (security_question_2 !== undefined) {
            updates.push('security_question_2 = ?');
            values.push(security_question_2);
        }
        if (security_answer_2 !== undefined && security_answer_2.trim() !== '') {
            console.log('ℹ️  Hashing security_answer_2...');
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
        const safeUpdates = [];
        
        for (const update of updates) {
            const column = update.split(' = ')[0].trim();
            console.log('ℹ️  Validating update:', update, 'Column:', column);
            if (!allowedColumns.includes(column)) {
                console.error('❌ Invalid column:', column);
                return res.status(400).json({
                    success: false,
                    message: 'Invalid column in update'
                });
            }
            // Ensure the update only contains column = ?
            if (!/^[a-z_0-9]+\s*=\s*\?$/i.test(update) && update !== 'updated_at = CURRENT_TIMESTAMP') {
                console.error('❌ Invalid format for update:', update);
                return res.status(400).json({
                    success: false,
                    message: 'Invalid update format'
                });
            }
            safeUpdates.push(update);
        }

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
        handleError(error, res, 'update profile');
    }
});

// Create new user - PROTECTED WITH JWT
app.post('/api/users', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const {
            first_name,
            last_name,
            username,
            email,
            password,
            account_status = 'active',
            two_factor_enabled = 'No',
            two_factor_method = 'email',
            two_factor_email,
            two_factor_phone,
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

        // Validate password strength (includes length check)
        const passwordStrength = security.validatePasswordStrength(password);
        if (!passwordStrength.valid) {
            return res.status(400).json({
                success: false,
                message: passwordStrength.errors.join('. ')
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
                two_factor_method,
                two_factor_email,
                two_factor_phone,
                role,
                security_question_1,
                security_answer_1_hash,
                security_question_2,
                security_answer_2_hash,
                token_expiration_minutes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            first_name,
            last_name,
            username,
            email,
            passwordHash,
            account_status,
            two_factor_enabled,
            two_factor_method,
            two_factor_email || null,
            two_factor_phone || null,
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
        handleError(error, res, 'create user');
    }
});

// Update user - PROTECTED WITH JWT
app.put('/api/users/:id', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
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
            two_factor_method,
            two_factor_email,
            two_factor_phone,
            two_factor_verified,
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
        if (password !== undefined && password !== null && password.trim() !== '') {
            // Validate password strength
            const passwordStrength = security.validatePasswordStrength(password);
            if (!passwordStrength.valid) {
                return res.status(400).json({
                    success: false,
                    message: passwordStrength.errors.join('. ')
                });
            }
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
        if (two_factor_method !== undefined) {
            const validMethods = ['email', 'sms', 'app'];
            if (!validMethods.includes(two_factor_method)) {
                return res.status(400).json({ success: false, message: 'Invalid 2FA method' });
            }
            updates.push('two_factor_method = ?');
            values.push(two_factor_method);
        }
        if (two_factor_email !== undefined) {
            if (two_factor_email && !validator.isEmail(two_factor_email)) {
                return res.status(400).json({ success: false, message: 'Invalid 2FA email format' });
            }
            updates.push('two_factor_email = ?');
            values.push(two_factor_email || null);
        }
        if (two_factor_phone !== undefined) {
            updates.push('two_factor_phone = ?');
            values.push(two_factor_phone || null);
        }
        if (two_factor_verified !== undefined) {
            if (typeof two_factor_verified !== 'boolean' && two_factor_verified !== 0 && two_factor_verified !== 1) {
                return res.status(400).json({ success: false, message: 'Invalid 2FA verified value' });
            }
            updates.push('two_factor_verified = ?');
            values.push(two_factor_verified);
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
        const allowedColumns = ['first_name', 'last_name', 'username', 'email', 'master_password_hash', 'account_status', 'two_factor_enabled', 'two_factor_method', 'two_factor_email', 'two_factor_phone', 'two_factor_verified', 'role', 'security_question_1', 'security_answer_1_hash', 'security_question_2', 'security_answer_2_hash', 'token_expiration_minutes', 'updated_at'];
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
        handleError(error, res, 'update user');
    }
});

// Delete user - PROTECTED WITH JWT
app.delete('/api/users/:id', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
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
        handleError(error, res, 'delete user');
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
        handleError(error, res, 'fetch application users');
    }
});

// Create app-user assignment
app.post('/api/app-users', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
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
        handleError(error, res, 'create app-user assignment');
    }
});

// Update app-user assignment
app.put('/api/app-users/:applicationId/:userId', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
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
        handleError(error, res, 'update app-user assignment');
    }
});

// Delete app-user assignment
app.delete('/api/app-users/:applicationId/:userId', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
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
        handleError(error, res, 'delete app-user assignment');
    }
});

// User applications endpoint
app.get('/api/user-applications', verifyToken, async (req, res) => {
    try {
        const userId = req.user.user_id;
        const [rows] = await pool.execute(`
            SELECT a.application_id, a.application_name, a.description, a.redirect_URL
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
        handleError(error, res, 'fetch user applications');
    }
});

// Login endpoint - UPDATED TO GENERATE JWT TOKENS
app.post('/api/auth/login', csrfProtection, csrfCrossOrigin, rateLimitLogin, security.accountLockoutMiddleware, async (req, res) => {
    try {
        const { username, password, twoFactorCode } = req.body;

        console.log(`ℹ️  Login attempt for username: ${username}`);

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Find user by username or email (excluding backup_codes initially for performance)
        const [users] = await pool.execute(
            'SELECT user_id, first_name, last_name, username, email, account_status, two_factor_enabled, two_factor_email, last_login_timestamp, master_password_hash, role FROM sa_users WHERE username = ? OR email = ?',
            [username, username]
        );

        if (users.length === 0) {
            console.error(`❌ User not found: ${username}`);
            security.recordFailedAttempt(username, req.ip);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const user = users[0];
        console.log(`ℹ️  User found: ${user.username}`);

        // Verify password
        const passwordValid = await bcrypt.compare(password, user.master_password_hash);

        if (!passwordValid) {
            console.error(`❌ Invalid password for user: ${username}`);
            const locked = security.recordFailedAttempt(username, req.ip);
            
            if (locked) {
                return res.status(423).json({
                    success: false,
                    message: 'Account locked due to multiple failed attempts. Try again in 30 minutes.'
                });
            }
            
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check account status (case insensitive)
        if (user.account_status.toLowerCase() !== 'active') {
            console.error(`❌ Account not active: ${user.account_status}`);
            security.auditLog('LOGIN_INACTIVE_ACCOUNT', { username, ip: req.ip });
            return res.status(403).json({
                success: false,
                message: 'Account is disabled'
            });
        }

        // Check if 2FA is enabled
        if (user.two_factor_enabled === 'Yes' || user.two_factor_enabled === 1) {
            const twoFactorKey = `${user.user_id}_${username}`;
            
            if (!twoFactorCode) {
                // Generate and send 2FA code (8 digits)
                const code = crypto.randomInt(10000000, 100000000).toString();
                const expiresInSeconds = 10 * 60; // 10 minutes
                
                await twoFactorStorage.set(twoFactorKey, { code, userId: user.user_id }, expiresInSeconds);
                
                // Send email with code
                let transporter;
                try {
                    const config = await loadSmtpConfig();
                    const port = parseInt(config.SMTP_PORT);
                    const secure = port === 465;
                    const transporter = nodemailer.createTransport({
                        host: config.SMTP_HOST,
                        port: port,
                        secure: secure,
                        auth: { user: config.SMTP_USER, pass: config.SMTP_PASSWORD },
                        tls: { rejectUnauthorized: true },
                        requireTLS: true
                    });
                    
                    const emailTo = user.two_factor_email || user.email;
                    await transporter.sendMail({
                        from: config.SMTP_FROM_EMAIL,
                        to: emailTo,
                        subject: 'SecureAccess - Your 2FA Code',
                        text: `Your 2-factor authentication code is: ${code}\n\nThis code will expire in 10 minutes.`
                    });
                    
                    console.log(`✅ 2FA code sent to ${emailTo}`);
                    security.auditLog('2FA_CODE_SENT', { username, email: emailTo, ip: req.ip });
                } catch (emailError) {
                    console.error('❌ Failed to send 2FA email:', emailError);
                    security.auditLog('2FA_EMAIL_FAILED', { username, ip: req.ip });
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to send 2FA code'
                    });
                } finally {
                    if (transporter) {
                        transporter.close();
                    }
                }
                
                return res.json({
                    success: false,
                    requiresTwoFactor: true,
                    message: '2FA code sent to your email'
                });
            } else {
                // Rate limit 2FA attempts (5 attempts per 10 minutes)
                const now = Date.now();
                const attemptKey = `${twoFactorKey}_${req.ip}`;
                
                if (!twoFactorAttempts.has(attemptKey)) {
                    twoFactorAttempts.set(attemptKey, { count: 0, resetTime: now + (10 * 60 * 1000) });
                }
                
                const attempts = twoFactorAttempts.get(attemptKey);
                
                if (now > attempts.resetTime) {
                    attempts.count = 0;
                    attempts.resetTime = now + (10 * 60 * 1000);
                }
                
                if (attempts.count >= 5) {
                    security.auditLog('2FA_RATE_LIMIT', { username, ip: req.ip });
                    return res.status(429).json({
                        success: false,
                        message: 'Too many 2FA attempts. Please try again later.'
                    });
                }
                
                attempts.count++;
                
                // Verify 2FA code
                const storedData = await twoFactorStorage.get(twoFactorKey);
                
                if (!storedData) {
                    security.auditLog('2FA_CODE_EXPIRED', { username, ip: req.ip });
                    return res.status(401).json({
                        success: false,
                        message: '2FA code expired or invalid'
                    });
                }
                
                // Only check expiration for in-memory storage (Redis handles expiration automatically)
                if (!useRedis && storedData.expiresAt && Date.now() > storedData.expiresAt) {
                    await twoFactorStorage.delete(twoFactorKey);
                    security.auditLog('2FA_CODE_EXPIRED', { username, ip: req.ip });
                    return res.status(401).json({
                        success: false,
                        message: '2FA code expired'
                    });
                }
                
                let codeValid = crypto.timingSafeEqual(
                    Buffer.from(storedData.code),
                    Buffer.from(twoFactorCode)
                );
                let usedBackupCode = false;
                
                // If regular code fails, try backup codes (fetch them now if needed)
                if (!codeValid) {
                    const [userWithBackup] = await pool.execute(
                        'SELECT backup_codes FROM sa_users WHERE user_id = ?',
                        [user.user_id]
                    );
                    if (userWithBackup.length > 0 && userWithBackup[0].backup_codes) {
                        try {
                            const backupCodes = safeJsonParse(userWithBackup[0].backup_codes, []);
                            const result = await verifyBackupCode(twoFactorCode, backupCodes);
                        
                        if (result.valid) {
                            codeValid = true;
                            usedBackupCode = true;
                            
                            // Update user's backup codes (remove used one)
                            await pool.execute(
                                'UPDATE sa_users SET backup_codes = ? WHERE user_id = ?',
                                [JSON.stringify(result.remainingCodes), user.user_id]
                            );
                            
                                console.log(`✅ Backup code used for user: ${username} (${result.remainingCodes.length} remaining)`);
                                security.auditLog('2FA_BACKUP_CODE_USED', { username, remaining: result.remainingCodes.length, ip: req.ip });
                            }
                        } catch (error) {
                            const errorMessage = error && error.message ? error.message : 'Unknown error';
                            console.error('Error verifying backup code:', errorMessage);
                        }
                    }
                }
                
                if (!codeValid) {
                    security.auditLog('2FA_CODE_INVALID', { username, ip: req.ip });
                    return res.status(401).json({
                        success: false,
                        message: 'Invalid 2FA code'
                    });
                }
                
                // Code is valid, delete it and clear attempts
                await twoFactorStorage.delete(twoFactorKey);
                twoFactorAttempts.delete(attemptKey);
                security.auditLog('2FA_SUCCESS', { username, ip: req.ip });
                console.log(`✅ 2FA code verified for user: ${username}`);
            }
        }

        // Clear failed attempts on successful login
        security.clearFailedAttempts(username);
        
        // Reset rate limit on successful login
        const ip = req.ip || req.connection.remoteAddress;
        if (loginAttempts.has(ip)) {
            loginAttempts.delete(ip);
        }

        // Generate JWT token
        const token = generateToken(user);
        console.log(`ℹ️  Generated JWT token for user: ${username}`);

        // Update last login timestamp
        await pool.execute(
            'UPDATE sa_users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
            [user.user_id]
        );

        security.auditLog('LOGIN_SUCCESS', { username, role: user.role, ip: req.ip });
        console.log(`✅ Login successful for user: ${username} (role: ${user.role})`);

        // Set JWT token as HTTP-only cookie
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: NODE_ENV === 'production',
            sameSite: 'strict',
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
        handleError(error, res, 'login');
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
app.post('/api/track-user', csrfProtection, csrfCrossOrigin, verifyToken, async (req, res) => {
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
        handleError(error, res, 'track application usage');
    }
});

// Get security questions - PUBLIC ACCESS (no CSRF protection)
app.post('/api/auth/security-questions', csrfProtection, csrfCrossOrigin, async (req, res) => {
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
        handleError(error, res, 'fetch security questions');
    }
});

// Verify security answer - PUBLIC ACCESS (no CSRF protection)
app.post('/api/auth/verify-security-answer', csrfProtection, csrfCrossOrigin, async (req, res) => {
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
        handleError(error, res, 'verify authentication');
    }
});

// Auth routes are handled directly in server.js

// Check if email exists
app.post('/api/auth/check-email', csrfProtection, csrfCrossOrigin, async (req, res) => {
    try {
        const { email } = req.body;
        const [rows] = await pool.execute('SELECT COUNT(*) as count FROM sa_users WHERE email = ?', [email]);
        res.json({ success: true, exists: rows[0].count > 0 });
    } catch (error) {
        handleError(error, res, 'check email');
    }
});

// Register new user from external app (IODD)
app.post('/api/register', csrfProtection, csrfCrossOrigin, async (req, res) => {
    try {
        const { firstName, lastName, email, username, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2, appKey, userRole } = req.body;
        
        const apiKey = req.headers['x-api-key'];
        const expectedApiKey = process.env.SECURE_API_SECRET || process.FVARS.SECURE_API_SECRET;
        if (!expectedApiKey || apiKey !== expectedApiKey) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const expectedAppKey = process.env.IODD_APP_KEY || process.FVARS.IODD_APP_KEY;
        if (!expectedAppKey || appKey !== expectedAppKey) {
            return res.status(403).json({ success: false, message: 'Invalid app key' });
        }

        if (!firstName || !lastName || !email || !username || !password) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        const [existingUser] = await pool.execute('SELECT user_id FROM sa_users WHERE email = ? OR username = ?', [email, username]);
        if (existingUser.length > 0) {
            return res.status(409).json({ success: false, message: 'User already exists' });
        }

        // Hash password and security answers
        const hashedPassword = await hashPassword(password);
        const hashedAnswer1 = securityAnswer1 ? await hashPassword(securityAnswer1) : null;
        const hashedAnswer2 = securityAnswer2 ? await hashPassword(securityAnswer2) : null;

        const [result] = await pool.execute(`
            INSERT INTO sa_users (first_name, last_name, email, username, master_password_hash, 
                security_question_1, security_answer_1_hash, security_question_2, security_answer_2_hash, 
                account_status, role) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', 'User')
        `, [firstName, lastName, email, username, hashedPassword, securityQuestion1, hashedAnswer1, securityQuestion2, hashedAnswer2]);

        if (!result || !result.insertId) {
            throw new Error('Failed to create user');
        }

        const [app] = await pool.execute('SELECT application_id FROM sa_applications WHERE app_key = ?', [appKey]);
        if (app.length > 0) {
            await pool.execute('INSERT INTO sa_app_user (application_id, user_id, app_role, status) VALUES (?, ?, ?, "Active")', [app[0].application_id, result.insertId, userRole || 'Member']);
        }

        res.json({ success: true, message: 'User created successfully', userId: result.insertId });
    } catch (error) {
        handleError(error, res, 'register user');
    }
});

// Create new user from PKCE token
app.post('/api/auth/create-user', csrfProtection, csrfCrossOrigin, async (req, res) => {
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
        handleError(error, res, 'create user from PKCE token');
    }
});

// Create app-user relationship
app.post('/api/auth/create-app-user', csrfProtection, csrfCrossOrigin, verifyToken, async (req, res) => {
    try {
        const { email, app_key, user_app_role } = req.body;
        console.log('ℹ️  Create app-user request for email:', email);

        const [userRows] = await pool.execute('SELECT user_id, first_name, last_name, username, email, role FROM sa_users WHERE email = ?', [email]);
        if (userRows.length === 0) {
            console.error('❌ User not found for email:', email);
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const user = userRows[0];
        console.log('ℹ️  Found user:', user.user_id, user.username);

        const [appRows] = await pool.execute('SELECT application_id, redirect_URL, failure_URL FROM sa_applications WHERE app_key = ?', [app_key]);
        if (appRows.length === 0) {
            console.error('❌ Application not found for app_key:', app_key);
            return res.status(404).json({ success: false, message: 'Application not found' });
        }

        const app = appRows[0];
        console.log('ℹ️  Found application:', app.application_id);

        console.log('ℹ️  Inserting sa_app_user record:', { application_id: app.application_id, user_id: user.user_id });
        await pool.execute('INSERT INTO sa_app_user (application_id, user_id, status, track_user, app_role) VALUES (?, ?, "Active", "No", "Member")', [app.application_id, user.user_id]);
        console.log('✅ sa_app_user record created successfully');

        // Always use redirect_URL from database, not from request
        let redirectUrl = app.redirect_URL;
        if (redirectUrl) {
            const userData = { 
                id: user.user_id, 
                userId: user.user_id,
                email: user.email,
                username: user.username,
                first_name: user.first_name, 
                last_name: user.last_name,
                roles: [user.role],
                permissions: []
            };
            const pkceToken = Buffer.from(JSON.stringify(userData)).toString('base64');
            const appToken = security.signAuthToken({ ...userData, exp: Date.now() + (24 * 60 * 60 * 1000) });
            redirectUrl += (redirectUrl.includes('?') ? '&' : '?') + `pkce=${pkceToken}&app_token=${encodeURIComponent(appToken)}`;
        }

        res.json({ success: true, message: 'App-user relationship created successfully', data: { redirect_url: redirectUrl } });
    } catch (error) {
        handleError(error, res, 'create app-user relationship');
    }
});

// Update password after security verification - PUBLIC ACCESS (no CSRF protection)
app.post('/api/auth/update-password', csrfProtection, csrfCrossOrigin, async (req, res) => {
    try {
        const { username, newPassword } = req.body;

        if (!username || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Username and new password are required'
            });
        }

        const passwordStrength = security.validatePasswordStrength(newPassword);
        if (!passwordStrength.valid) {
            return res.status(400).json({
                success: false,
                message: passwordStrength.errors.join('. ')
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

        security.auditLog('PASSWORD_RESET', { username, ip: req.ip });
        console.log(`ℹ️  Password updated for user: ${username}`);

        res.json({
            success: true,
            message: 'Password updated successfully'
        });

    } catch (error) {
        handleError(error, res, 'update password');
    }
});

// SMTP Configuration endpoints
app.get('/api/sms-providers', adminAccess, async (req, res) => {
    const providersPath = path.join(__dirname, '../data/sms-providers.json');
    
    // Validate path to prevent traversal
    const resolvedPath = path.resolve(providersPath);
    const baseDir = path.resolve(__dirname, '../data');
    if (!resolvedPath.startsWith(baseDir) || !resolvedPath.endsWith('sms-providers.json')) {
        return res.status(400).json({ success: false, message: 'Invalid file path' });
    }
    
    try {
        const content = await fs.readFile(resolvedPath, 'utf8');
        const data = safeJsonParse(content, {});
        res.json(data);
    } catch (error) {
        handleError(error, res, 'load SMS providers', 500, 'Failed to load SMS providers');
    }
});

app.post('/api/test-2fa', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
    let transporter;
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: 'No email specified' });
        }
        const smtpPath = path.join(__dirname, '.env.SMTP');
        const smtpContent = await fs.readFile(smtpPath, 'utf8');
        const lines = smtpContent.split('\n');
        const config = {};
        const maxLines = 50;
        const lineCount = Math.min(lines.length, maxLines);
        for (let i = 0; i < lineCount; i++) {
            const match = lines[i].match(/^([A-Z_]+)=([^\r\n]*)$/);
            if (match) config[match[1]] = match[2].replace(/"/g, '');
        }
        const port = parseInt(config.SMTP_PORT);
        const secure = port === 465;
        transporter = nodemailer.createTransport({
            host: config.SMTP_HOST,
            port: port,
            secure: secure,
            auth: { user: config.SMTP_USER, pass: config.SMTP_PASSWORD },
            tls: { rejectUnauthorized: true },
            requireTLS: true
        });
        await transporter.sendMail({
            from: config.SMTP_FROM_EMAIL,
            to: email,
            subject: 'SecureAccess 2-Factor Test',
            text: 'SecureAccess 2-Factor Test Message.'
        });
        res.json({ success: true, message: 'Test message sent successfully' });
    } catch (error) {
        handleError(error, res, 'send 2FA test email', 500, error.message);
    } finally {
        if (transporter) {
            transporter.close();
        }
    }
});

app.get('/api/smtp-config', adminAccess, async (req, res) => {
    const smtpPath = path.join(__dirname, '.env.SMTP');
    try {
        const content = await fs.readFile(smtpPath, 'utf8');
        res.json({ success: true, content });
    } catch (error) {
        handleError(error, res, 'load SMTP config', 500, 'Failed to load SMTP config');
    }
});

app.post('/api/smtp-config', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
    const smtpPath = path.join(__dirname, '.env.SMTP');
    
    // Validate path to prevent traversal
    if (smtpPath.includes('..') || smtpPath.includes('~')) {
        return res.status(400).json({ success: false, message: 'Invalid file path' });
    }
    
    const resolvedPath = path.resolve(smtpPath);
    const baseDir = path.resolve(__dirname);
    if (!resolvedPath.startsWith(baseDir)) {
        return res.status(400).json({ success: false, message: 'Invalid file path' });
    }
    
    // Additional check: ensure the resolved path ends with the expected filename
    if (!resolvedPath.endsWith('.env.SMTP')) {
        return res.status(400).json({ success: false, message: 'Invalid file path' });
    }
    
    try {
        const content = req.body.content;
        
        // Validate content is a string
        if (typeof content !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid content type' });
        }
        
        // Validate content length first to prevent ReDoS attacks
        if (content.length > 10000) {
            return res.status(400).json({ success: false, message: 'Content too large' });
        }
        
        // Validate content only contains allowed characters for .env file
        // Allow alphanumeric, common punctuation, and whitespace for SMTP config
        // Note: Content length is validated above to prevent ReDoS
        const allowedCharsRegex = /^[A-Za-z0-9_=@.\-:\/\s\n"'#]+$/;
        if (!allowedCharsRegex.test(content)) {
            return res.status(400).json({ success: false, message: 'Invalid characters in content' });
        }
        
        // Prevent null byte injection
        if (content.includes('\0') || content.includes('%00')) {
            return res.status(400).json({ success: false, message: 'Invalid content' });
        }
        
        // Validate content structure: each non-empty line must be KEY=VALUE format
        const contentLines = content.split('\n');
        const envLineRegex = /^[A-Z_]+=[^\r\n]*$/;
        for (const line of contentLines) {
            const trimmedLine = line.trim();
            // Validate line length to prevent ReDoS
            if (trimmedLine.length > 500) {
                return res.status(400).json({ success: false, message: 'Line too long in .env file' });
            }
            if (trimmedLine && !trimmedLine.startsWith('#') && !envLineRegex.test(trimmedLine)) {
                return res.status(400).json({ success: false, message: 'Invalid .env file format' });
            }
        }
        
        // Write file with restricted permissions (read/write for owner only, no execute)
        await fs.writeFile(resolvedPath, content, { encoding: 'utf8', mode: 0o600 });
        res.json({ success: true, message: 'SMTP config saved' });
    } catch (error) {
        handleError(error, res, 'save SMTP config', 500, 'Failed to save SMTP config');
    }
});

app.post('/api/smtp-test', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
    let transporter;
    try {
        const { content, testEmail } = req.body;
        const lines = content.split('\n');
        const config = {};
        const maxLines = 50;
        const lineCount = Math.min(lines.length, maxLines);
        for (let i = 0; i < lineCount; i++) {
            const match = lines[i].match(/^([A-Z_]+)=([^\r\n]*)$/);
            if (match) config[match[1]] = match[2].replace(/"/g, '');
        }
        const port = parseInt(config.SMTP_PORT);
        const secure = port === 465;
        transporter = nodemailer.createTransport({
            host: config.SMTP_HOST,
            port: port,
            secure: secure,
            auth: { user: config.SMTP_USER, pass: config.SMTP_PASSWORD },
            tls: { rejectUnauthorized: true },
            requireTLS: true
        });
        await transporter.verify();
        if (testEmail) {
            await transporter.sendMail({
                from: config.SMTP_FROM_EMAIL,
                to: testEmail,
                subject: 'SMTP Test Message',
                text: 'This is a test email from SecureAccess SMTP configuration.'
            });
        }
        res.json({ success: true, message: 'SMTP connection successful' });
    } catch (error) {
        handleError(error, res, 'test SMTP connection', 500, error.message);
    } finally {
        if (transporter) {
            transporter.close();
        }
    }
});

// Generate backup codes for user
app.post('/api/users/:id/backup-codes', csrfProtection, csrfCrossOrigin, adminAccess, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        // Generate new backup codes
        const codes = generateBackupCodes();
        const hashedCodes = await hashBackupCodes(codes);
        
        // Store hashed codes in database
        await pool.execute(
            'UPDATE sa_users SET backup_codes = ? WHERE user_id = ?',
            [JSON.stringify(hashedCodes), userId]
        );
        
        security.auditLog('BACKUP_CODES_GENERATED', { userId, ip: req.ip });
        
        // Return plain codes to admin (only time they're visible)
        res.json({
            success: true,
            message: 'Backup codes generated successfully',
            codes: codes
        });
    } catch (error) {
        handleError(error, res, 'generate backup codes');
    }
});

// Get audit logs (admin only)
app.get('/api/admin/audit-logs', adminAccess, (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const logs = security.getAuditLogs(limit);
        
        res.json({
            success: true,
            data: logs
        });
    } catch (error) {
        handleError(error, res, 'fetch audit logs');
    }
});

// Health check endpoint (no CSRF needed)
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: 'connected'
    });
});

app.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Suppress Chrome DevTools 404 error
app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => {
    res.status(204).end();
});

// API health check
app.get('/api', (req, res) => {
    res.json({
        status: 'OK',
        message: 'SecureAccess API is running',
        timestamp: new Date().toISOString()
    });
});

// Config endpoint
app.get('/config', verifyToken, (req, res) => {
    res.json({
        port: PORT,
        host: HOST,
        environment: NODE_ENV,
        apiBaseUrl: `${BASE_URL}/api`
    });
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
        await initRedis();

        listRoutes()

        server = app.listen(PORT, () => {
            console.log(`📊 Admin page:   ${SECURE_PATH}/admin-users.html`);
            console.log(`📊 Login page:   ${SECURE_PATH}/index.html`);
            console.log(`🏥 Health check: ${BASE_URL}/health`);
            console.log(`🌍 Environment:  ${NODE_ENV}`);
            console.log(`🔐 JWT Security: ENABLED`);

            console.log(`\n✅ Server is running at: ${BASE_URL}`);
        });

    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
let server;

async function gracefulShutdown(signal) {
    console.log(`\nℹ️  Received ${signal}. Shutting down server...`);

    // Clear cleanup interval
    if (cleanupInterval) {
        clearInterval(cleanupInterval);
        cleanupInterval = null;
        console.log('🛑 Cleanup interval cleared');
    }

    if (server) {
        server.close(() => {
            console.log('🛑 HTTP server closed');
        });
    }

    if (pool) {
        try {
            await pool.end();
            console.log('🛑 Database connections closed');
        } catch (error) {
            console.error('Error closing database:', error.message);
        }
    }
    
    if (redisClient && useRedis) {
        try {
            await redisClient.quit();
            console.log('🛑 Redis connection closed');
        } catch (error) {
            console.error('Error closing Redis:', error.message);
        }
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
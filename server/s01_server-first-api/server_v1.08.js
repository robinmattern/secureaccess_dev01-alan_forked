const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const validator = require('validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 54333;

// Middleware
app.use(cors({
    origin: ['http://localhost:54333', 'http://127.0.0.1:8080', 'http://localhost:54383',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Id', 'x-session-id', 'x-requested-with', 'x-csrf-token'],
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
app.use(express.static(path.join(__dirname, '../../client/c01_client-first-app'))); // Serve static files

// Request logging middleware
app.use((req, res, next) => {
    console.log(`🔍 ${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Simple session store
const activeSessions = new Map();

// CSRF token store
const csrfTokens = new Map();

// Rate limiting store
const loginAttempts = new Map();

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

// Generate CSRF token
function generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
}

// CSRF protection middleware
function csrfProtection(req, res, next) {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }
    
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    const sessionId = req.headers['authorization']?.replace('Bearer ', '');
    
    if (!token || !sessionId || !csrfTokens.has(sessionId) || csrfTokens.get(sessionId) !== token) {
        return res.status(403).json({
            success: false,
            message: 'Invalid CSRF token'
        });
    }
    
    next();
}

// Admin access middleware
function adminAccess(req, res, next) {
    const authHeader = req.headers['authorization'];
    const sessionId = authHeader ? authHeader.replace('Bearer ', '') : null;
    
    if (!sessionId || !activeSessions.has(sessionId)) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }
    
    const session = activeSessions.get(sessionId);
    if (!session || session.role !== 'Admin') {
        return res.status(403).json({
            success: false,
            message: 'Admin access required'
        });
    }
    
    // Check session expiration (1 hour)
    if (Date.now() - session.createdAt.getTime() > 3600000) {
        activeSessions.delete(sessionId);
        csrfTokens.delete(sessionId);
        return res.status(401).json({
            success: false,
            message: 'Session expired'
        });
    }
    
    req.user = session;
    next();
}

// User access middleware (for regular users)
function userAccess(req, res, next) {
    const authHeader = req.headers['authorization'];
    const sessionId = authHeader ? authHeader.replace('Bearer ', '') : null;
    
    if (!sessionId || !activeSessions.has(sessionId)) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }
    
    const session = activeSessions.get(sessionId);
    if (!session) {
        return res.status(401).json({
            success: false,
            message: 'Invalid session'
        });
    }
    
    // Check session expiration (1 hour)
    if (Date.now() - session.createdAt.getTime() > 3600000) {
        activeSessions.delete(sessionId);
        csrfTokens.delete(sessionId);
        return res.status(401).json({
            success: false,
            message: 'Session expired'
        });
    }
    
    req.user = session;
    next();
}

// Database configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'user',
    password: process.env.DB_PASSWORD || 'password',
    database: process.env.DB_NAME || 'secureaccess2',
    timezone: 'Z'
};

// Database connection pool
let pool;

async function initDatabase() {
    try {
        if (!dbConfig.host || !dbConfig.user || !dbConfig.password) {
            throw new Error('Database configuration incomplete. Please set DB_HOST, DB_USER, and DB_PASSWORD environment variables.');
        }
        
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
        const createUsersTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                first_name VARCHAR(50),
                last_name VARCHAR(50),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                master_password_hash VARCHAR(255) NOT NULL,
                account_status ENUM('active', 'inactive', 'locked') DEFAULT 'active',
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
            )
        `;
        
        await pool.execute(createUsersTableSQL);
        console.log('✅ sa_users table verified/created');
        
        const createApplicationsTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_applications (
                application_id INT AUTO_INCREMENT PRIMARY KEY,
                application_name VARCHAR(100) NOT NULL,
                description TEXT,
                redirect_URL VARCHAR(255),
                parm_email ENUM('Yes', 'No') DEFAULT 'No',
                parm_username ENUM('Yes', 'No') DEFAULT 'No',
                parm_PKCE ENUM('Yes', 'No') DEFAULT 'No',
                status ENUM('Active', 'Inactive') DEFAULT 'Inactive',
                date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `;
        
        await pool.execute(createApplicationsTableSQL);
        console.log('✅ sa_applications table created with correct structure');
        
        const createAppUserTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_app_user (
                application_id INT NOT NULL,
                user_id INT NOT NULL,
                status ENUM('Active', 'Inactive', 'Temp Use') DEFAULT 'Inactive',
                start_date DATE NULL,
                end_date DATE NULL,
                track_user ENUM('Yes', 'No') DEFAULT 'No',
                date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                date_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (application_id, user_id),
                FOREIGN KEY (application_id) REFERENCES sa_applications(application_id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES sa_users(user_id) ON DELETE CASCADE
            )
        `;
        
        await pool.execute(createAppUserTableSQL);
        console.log('✅ sa_app_user table created with correct structure');
        
        const createTrackingUserTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_tracking_user (
                track_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                application_id INT NOT NULL,
                event_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                computer_name VARCHAR(255),
                computer_MAC VARCHAR(17),
                computer_ip VARCHAR(45),
                FOREIGN KEY (application_id) REFERENCES sa_applications(application_id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES sa_users(user_id) ON DELETE CASCADE
            )
        `;
        
        await pool.execute(createTrackingUserTableSQL);
        console.log('✅ sa_tracking_user table created with correct structure');
        
        // Add parm_PKCE column if it doesn't exist
        try {
            await pool.execute('ALTER TABLE sa_applications ADD COLUMN parm_PKCE ENUM(\'Yes\', \'No\') DEFAULT \'No\'');
            console.log('✅ Added parm_PKCE column to sa_applications table');
        } catch (error) {
            if (error.code === 'ER_DUP_FIELDNAME') {
                console.log('✅ parm_PKCE column already exists');
            } else {
                console.error('❌ Error adding parm_PKCE column:', error.message);
            }
        }
        
        // Add app_run_count column if it doesn't exist
        try {
            await pool.execute('ALTER TABLE sa_applications ADD COLUMN app_run_count INT DEFAULT 0');
            console.log('✅ Added app_run_count column to sa_applications table');
        } catch (error) {
            if (error.code === 'ER_DUP_FIELDNAME') {
                console.log('✅ app_run_count column already exists');
            } else {
                console.error('❌ Error adding app_run_count column:', error.message);
            }
        }
        
        // Add track_user column to sa_app_user if it doesn't exist
        try {
            await pool.execute('ALTER TABLE sa_app_user ADD COLUMN track_user ENUM(\'Yes\', \'No\') DEFAULT \'No\'');
            console.log('✅ Added track_user column to sa_app_user table');
        } catch (error) {
            if (error.code === 'ER_DUP_FIELDNAME') {
                console.log('✅ track_user column already exists');
            } else {
                console.error('❌ Error adding track_user column:', error.message);
            }
        }
        
        // Add app_role column to sa_app_user if it doesn't exist
        try {
            await pool.execute('ALTER TABLE sa_app_user ADD COLUMN app_role VARCHAR(100) NULL');
            console.log('✅ Added app_role column to sa_app_user table');
        } catch (error) {
            if (error.code === 'ER_DUP_FIELDNAME') {
                console.log('✅ app_role column already exists');
            } else {
                console.error('❌ Error adding app_role column:', error.message);
            }
        }
        
        // Add security_roles column to sa_applications if it doesn't exist
        try {
            await pool.execute('ALTER TABLE sa_applications ADD COLUMN security_roles VARCHAR(500) NULL');
            console.log('✅ Added security_roles column to sa_applications table');
        } catch (error) {
            if (error.code === 'ER_DUP_FIELDNAME') {
                console.log('✅ security_roles column already exists');
            } else {
                console.error('❌ Error adding security_roles column:', error.message);
            }
        }
        
        // Add app_key column to sa_applications if it doesn't exist
        try {
            await pool.execute('ALTER TABLE sa_applications ADD COLUMN app_key VARCHAR(50) UNIQUE NULL');
            console.log('✅ Added app_key column to sa_applications table');
        } catch (error) {
            if (error.code === 'ER_DUP_FIELDNAME') {
                console.log('✅ app_key column already exists');
            } else {
                console.error('❌ Error adding app_key column:', error.message);
            }
        }
        
    } catch (error) {
        console.error('❌ Error creating tables:', error.message);
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
        console.error('Password verification error:', error.message);
        return false;
    }
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        database: 'connected'
    });
});



// Get current user profile (for regular users) - MOVED UP to avoid conflict with /api/users/:id
app.get('/api/users/me', userAccess, async (req, res) => {
    console.log('✅ GET /api/users/me called with userAccess middleware');
    try {
        const userId = req.user.userId;
        
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
                security_question_1,
                security_question_2,
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
        console.error('Error fetching user profile:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch profile',
            error: error.message
        });
    }
});

// Update current user profile (for regular users) - MOVED UP to avoid conflict with /api/users/:id
app.put('/api/users/me', csrfProtection, userAccess, async (req, res) => {
    console.log('✅ PUT /api/users/me called with userAccess middleware');
    try {
        const userId = req.user.userId;
        
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
        
        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
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
                user_id,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                security_question_1,
                security_question_2,
                token_expiration_minutes,
                updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: updatedUser[0]
        });
        
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile',
            error: error.message
        });
    }
});

// Get CSRF token
app.get('/api/csrf-token', (req, res) => {
    const sessionId = req.headers['authorization']?.replace('Bearer ', '');
    if (!sessionId || !activeSessions.has(sessionId)) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }
    
    const token = generateCSRFToken();
    csrfTokens.set(sessionId, token);
    
    res.json({
        success: true,
        token: token
    });
});

// Get all users
app.get('/api/users', adminAccess, async (req, res) => {
    try {
        console.log('📊 GET /api/users - Loading all users...');
        
        if (!pool) {
            console.error('❌ Database pool not initialized');
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
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
                role,
                token_expiration_minutes,
                last_login_timestamp,
                created_at,
                updated_at
            FROM sa_users 
            ORDER BY first_name, last_name
        `);
        
        console.log(`✅ Found ${rows.length} users`);
        
        res.json({
            success: true,
            data: rows
        });
        
    } catch (error) {
        console.error('❌ Error fetching users:');
        console.error('Error code:', error.code);
        console.error('Error message:', error.message);
        console.error('SQL State:', error.sqlState);
        console.error('Full error:', error);
        
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users',
            error: error.message,
            details: error.code
        });
    }
});

// Get specific user by ID
app.get('/api/users/:id', adminAccess, async (req, res) => {
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
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user',
            error: error.message
        });
    }
});

// Create new user
app.post('/api/users', adminAccess, csrfProtection, async (req, res) => {
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
            console.log('🔐 Hashed security_answer_1 for new user');
        }
        
        if (security_answer_2 && security_answer_2.trim() !== '') {
            hashedAnswer2 = await hashPassword(security_answer_2.trim());
            console.log('🔐 Hashed security_answer_2 for new user');
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

// Update user - FIXED VERSION WITH ENHANCED LOGGING
app.put('/api/users/:id', adminAccess, csrfProtection, async (req, res) => {
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
        
        console.log('🔄 Update request for user ID:', userId);
        console.log('📝 Received data:', {
            first_name,
            last_name,
            username,
            email,
            security_question_1,
            security_answer_1: security_answer_1 ? '[PROVIDED]' : '[NOT PROVIDED]',
            security_question_2,
            security_answer_2: security_answer_2 ? '[PROVIDED]' : '[NOT PROVIDED]'
        });
        
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
            console.log('📋 Updating security_question_1:', security_question_1);
            updates.push('security_question_1 = ?');
            values.push(security_question_1);
        }
        
        // FIXED: Security Answer 1 handling
        if (security_answer_1 !== undefined && security_answer_1.trim() !== '') {
            console.log('🔐 Hashing security_answer_1...');
            const hashedAnswer1 = await hashPassword(security_answer_1.trim());
            updates.push('security_answer_1_hash = ?');
            values.push(hashedAnswer1);
            console.log('✅ security_answer_1_hash updated');
        }
        
        if (security_question_2 !== undefined) {
            console.log('📋 Updating security_question_2:', security_question_2);
            updates.push('security_question_2 = ?');
            values.push(security_question_2);
        }
        
        // FIXED: Security Answer 2 handling
        if (security_answer_2 !== undefined && security_answer_2.trim() !== '') {
            console.log('🔐 Hashing security_answer_2...');
            const hashedAnswer2 = await hashPassword(security_answer_2.trim());
            updates.push('security_answer_2_hash = ?');
            values.push(hashedAnswer2);
            console.log('✅ security_answer_2_hash updated');
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
        const allowedColumns = ['first_name', 'last_name', 'username', 'email', 'master_password_hash', 'security_question_1', 'security_answer_1_hash', 'security_question_2', 'security_answer_2_hash', 'updated_at'];
        const safeUpdates = updates.filter(update => {
            const column = update.split(' = ')[0];
            return allowedColumns.includes(column);
        });
        
        const updateSQL = `UPDATE sa_users SET ${safeUpdates.join(', ')} WHERE user_id = ?`;
        
        console.log('🗃️ Executing SQL:', updateSQL);
        console.log('📊 With values:', values.map((v, i) => 
            values.length - 1 === i ? `userId: ${v}` : 
            updates[i]?.includes('password') || updates[i]?.includes('answer') ? '[HASHED]' : v
        ));
        
        const [updateResult] = await pool.execute(updateSQL, values);
        
        console.log('✅ Update result:', {
            affectedRows: updateResult.affectedRows,
            changedRows: updateResult.changedRows
        });
        
        // Fetch updated user data
        const [updatedUser] = await pool.execute(`
            SELECT 
                user_id,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                security_question_1,
                security_question_2,
                token_expiration_minutes,
                updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
        res.json({
            success: true,
            message: 'User updated successfully',
            data: updatedUser[0]
        });
        
    } catch (error) {
        console.error('❌ Error updating user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user',
            error: error.message
        });
    }
});

// Delete user and related records
app.delete('/api/users/:id', adminAccess, csrfProtection, async (req, res) => {
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
        
        // Start transaction for safe deletion
        const connection = await pool.getConnection();
        await connection.beginTransaction();
        
        try {
            // Delete related records from other tables (add as needed)
            // Example: await connection.execute('DELETE FROM user_sessions WHERE user_id = ?', [userId]);
            // Example: await connection.execute('DELETE FROM user_tokens WHERE user_id = ?', [userId]);
            // Example: await connection.execute('DELETE FROM user_logs WHERE user_id = ?', [userId]);
            
            // Delete the user
            await connection.execute('DELETE FROM sa_users WHERE user_id = ?', [userId]);
            
            await connection.commit();
            connection.release();
            
            res.json({
                success: true,
                message: `User ${existingUser[0].username} deleted successfully`
            });
            
        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user',
            error: error.message
        });
    }
});



// Reset password for a single user
app.post('/api/admin/reset-single-password', adminAccess, csrfProtection, async (req, res) => {
    try {
        const { username, newPassword } = req.body;
        
        if (!username || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Username and newPassword are required'
            });
        }
        
        if (!pool) {
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Hash the new password
        const passwordHash = await hashPassword(newPassword);
        
        // Update the user's password
        const [result] = await pool.execute(
            'UPDATE sa_users SET master_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?',
            [passwordHash, username]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        console.log(`✅ Password reset for user: ${username}`);
        
        res.json({
            success: true,
            message: `Password reset successfully for user: ${username}`
        });
        
    } catch (error) {
        console.error('❌ Error resetting password:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password',
            error: error.message
        });
    }
});

// Bulk fix passwords for users with NULL password_hash
app.post('/api/admin/fix-passwords', adminAccess, csrfProtection, async (req, res) => {
    try {
        const { defaultPassword = 'password123' } = req.body;
        
        if (!pool) {
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Find all users with NULL or empty master_password_hash
        const [usersWithoutPasswords] = await pool.execute(
            'SELECT user_id, username FROM sa_users WHERE master_password_hash IS NULL OR master_password_hash = ""'
        );
        
        if (usersWithoutPasswords.length === 0) {
            return res.json({
                success: true,
                message: 'All users already have password hashes',
                fixed_count: 0
            });
        }
        
        // Hash the default password
        const passwordHash = await hashPassword(defaultPassword);
        
        // Update all users without password hashes
        const [result] = await pool.execute(
            'UPDATE sa_users SET master_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE master_password_hash IS NULL OR master_password_hash = ""',
            [passwordHash]
        );
        
        console.log(`✅ Fixed password hashes for ${result.affectedRows} users with default password: ${defaultPassword}`);
        
        res.json({
            success: true,
            message: `Fixed password hashes for ${result.affectedRows} users`,
            fixed_count: result.affectedRows,
            default_password: defaultPassword,
            affected_users: usersWithoutPasswords.map(u => u.username)
        });
        
    } catch (error) {
        console.error('❌ Error fixing passwords:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fix passwords',
            error: error.message
        });
    }
});


// Get user applications (for app launcher)
app.get('/api/user-applications', userAccess, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        const [rows] = await pool.execute(`
            SELECT APP.application_name, APP.application_id, USR.user_id
            FROM sa_applications APP
            INNER JOIN sa_app_user AU ON AU.application_id = APP.application_id
            INNER JOIN sa_users USR ON USR.user_id = AU.user_id
            WHERE 
               USR.user_id = ? AND 
               APP.status = 'Active' AND
               (AU.status = 'Active' OR (AU.status = 'Temp Use' AND AU.start_date <= CURDATE() AND AU.end_date >= CURDATE()))
            ORDER BY 
               APP.application_name
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

// Logout endpoint
app.post('/api/auth/logout', csrfProtection, userAccess, (req, res) => {
    try {
        const sessionId = req.headers['authorization']?.replace('Bearer ', '');
        
        if (sessionId) {
            activeSessions.delete(sessionId);
            csrfTokens.delete(sessionId);
        }
        
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
        
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({
            success: false,
            message: 'Logout failed',
            error: error.message
        });
    }
});

// Get current user info (for authentication check)
app.get('/api/auth/me', userAccess, async (req, res) => {
    try {
        res.json({
            success: true,
            data: {
                user_id: req.user.userId,
                username: req.user.username,
                role: req.user.role
            }
        });
        
    } catch (error) {
        console.error('Error fetching current user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch current user',
            error: error.message
        });
    }
});

// Get current user's assignment to specific application
app.get('/api/my-app-assignment/:applicationId', userAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        const userId = req.user.userId;
        
        if (isNaN(applicationId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                au.application_id,
                au.user_id,
                au.app_role,
                au.status,
                au.start_date,
                au.end_date,
                au.track_user
            FROM sa_app_user au
            WHERE au.application_id = ? AND au.user_id = ?
        `, [applicationId, userId]);
        
        res.json({
            success: true,
            data: rows[0] || null
        });
        
    } catch (error) {
        console.error('Error fetching user app assignment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user app assignment',
            error: error.message
        });
    }
});

// Get computer information
app.get('/api/computer-info', userAccess, async (req, res) => {
    try {
        const os = require('os');
        const { execSync } = require('child_process');
        
        let computerName = os.hostname();
        let computerIP = 'Unknown';
        let computerMAC = 'Unknown';
        
        // Get IP address
        const networkInterfaces = os.networkInterfaces();
        for (const interfaceName in networkInterfaces) {
            const interfaces = networkInterfaces[interfaceName];
            for (const iface of interfaces) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    computerIP = iface.address;
                    computerMAC = iface.mac;
                    break;
                }
            }
            if (computerIP !== 'Unknown') break;
        }
        
        res.json({
            success: true,
            data: {
                computer_name: computerName,
                computer_ip: computerIP,
                computer_MAC: computerMAC
            }
        });
        
    } catch (error) {
        console.error('Error getting computer info:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get computer info',
            error: error.message
        });
    }
});



// Get all applications
app.get('/api/applications', userAccess, async (req, res) => {
    try {
        console.log('🔍 GET /api/applications - Loading all applications...');
        
        const [rows] = await pool.execute(`
            SELECT 
                application_id,
                application_name,
                description,
                redirect_URL,
                security_roles,
                parm_email,
                parm_username,
                parm_PKCE,
                status,
                app_key,
                app_run_count,
                date_created,
                date_updated
            FROM sa_applications 
            ORDER BY application_name
        `);
        
        console.log(`✅ Found ${rows.length} applications:`, rows);
        
        res.json({
            success: true,
            data: rows
        });
        
    } catch (error) {
        console.error('❌ Error fetching applications:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch applications',
            error: error.message
        });
    }
});

// Get application by app_key
app.get('/api/applications/by-key/:appKey', async (req, res) => {
    try {
        const appKey = req.params.appKey;
        
        const [rows] = await pool.execute(`
            SELECT 
                application_id,
                application_name,
                description,
                redirect_URL,
                security_roles,
                parm_email,
                parm_username,
                parm_PKCE,
                status,
                app_run_count,
                date_created,
                date_updated
            FROM sa_applications 
            WHERE app_key = ? AND status = 'Active'
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

// Get specific application by ID
app.get('/api/applications/:id', userAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.id);
        
        if (isNaN(applicationId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                application_id,
                application_name,
                description,
                redirect_URL,
                security_roles,
                parm_email,
                parm_username,
                parm_PKCE,
                status,
                app_key,
                app_run_count,
                date_created,
                date_updated
            FROM sa_applications 
            WHERE application_id = ?
        `, [applicationId]);
        
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
app.post('/api/applications', adminAccess, csrfProtection, async (req, res) => {
    try {
        const {
            application_name,
            description,
            redirect_URL,
            security_roles,
            parm_email = 'No',
            parm_username = 'No',
            parm_PKCE = 'No',
            status = 'Inactive',
            app_key
        } = req.body;
        
        if (!application_name) {
            return res.status(400).json({
                success: false,
                message: 'Application name is required'
            });
        }
        
        const [result] = await pool.execute(`
            INSERT INTO sa_applications (
                application_name,
                description,
                redirect_URL,
                security_roles,
                parm_email,
                parm_username,
                parm_PKCE,
                status,
                app_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            application_name,
            description || null,
            redirect_URL || null,
            security_roles || null,
            parm_email,
            parm_username,
            parm_PKCE,
            status,
            app_key || null
        ]);
        
        res.status(201).json({
            success: true,
            message: 'Application created successfully',
            data: {
                application_id: result.insertId,
                application_name,
                description,
                redirect_URL,
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
app.put('/api/applications/:id', adminAccess, csrfProtection, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.id);
        
        if (isNaN(applicationId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID'
            });
        }
        
        const {
            application_name,
            description,
            redirect_URL,
            security_roles,
            parm_email,
            parm_username,
            parm_PKCE,
            status,
            app_key
        } = req.body;
        
        if (!application_name) {
            return res.status(400).json({
                success: false,
                message: 'Application name is required'
            });
        }
        
        const [result] = await pool.execute(`
            UPDATE sa_applications 
            SET 
                application_name = ?,
                description = ?,
                redirect_URL = ?,
                security_roles = ?,
                parm_email = ?,
                parm_username = ?,
                parm_PKCE = ?,
                status = ?,
                app_key = ?,
                date_updated = CURRENT_TIMESTAMP
            WHERE application_id = ?
        `, [
            application_name,
            description || null,
            redirect_URL || null,
            security_roles || null,
            parm_email || 'No',
            parm_username || 'No',
            parm_PKCE || 'No',
            status || 'Inactive',
            app_key || null,
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
app.delete('/api/applications/:id', adminAccess, csrfProtection, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.id);
        
        if (isNaN(applicationId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID'
            });
        }
        
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

// Get specific app-user assignment
app.get('/api/app-users/:applicationId/:userId', userAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        const userId = parseInt(req.params.userId);
        
        if (isNaN(applicationId) || isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID or user ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                au.application_id,
                au.user_id,
                au.app_role,
                au.status,
                au.start_date,
                au.end_date,
                au.track_user,
                au.date_created,
                au.date_updated
            FROM sa_app_user au
            WHERE au.application_id = ? AND au.user_id = ?
        `, [applicationId, userId]);
        
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User assignment not found'
            });
        }
        
        res.json({
            success: true,
            data: rows[0]
        });
        
    } catch (error) {
        console.error('Error fetching app-user assignment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch app-user assignment',
            error: error.message
        });
    }
});

// Get users assigned to application
app.get('/api/app-users/:applicationId', adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        
        if (isNaN(applicationId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                au.application_id,
                au.user_id,
                au.app_role,
                au.status,
                au.start_date,
                au.end_date,
                au.track_user,
                au.date_created,
                au.date_updated,
                u.first_name,
                u.last_name,
                u.username,
                u.email
            FROM sa_app_user au
            JOIN sa_users u ON au.user_id = u.user_id
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

// Assign user to application
app.post('/api/app-users', adminAccess, csrfProtection, async (req, res) => {
    try {
        const {
            application_id,
            user_id,
            app_role,
            status = 'Inactive',
            start_date,
            end_date,
            track_user = 'No'
        } = req.body;
        
        if (!application_id || !user_id) {
            return res.status(400).json({
                success: false,
                message: 'Application ID and User ID are required'
            });
        }
        
        // Check if assignment already exists
        const [existing] = await pool.execute(
            'SELECT * FROM sa_app_user WHERE application_id = ? AND user_id = ?',
            [application_id, user_id]
        );
        
        if (existing.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'User is already assigned to this application'
            });
        }
        
        const [result] = await pool.execute(`
            INSERT INTO sa_app_user (
                application_id,
                user_id,
                app_role,
                status,
                start_date,
                end_date,
                track_user
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            application_id,
            user_id,
            app_role || null,
            status,
            start_date || null,
            end_date || null,
            track_user
        ]);
        
        res.status(201).json({
            success: true,
            message: 'User assigned to application successfully'
        });
        
    } catch (error) {
        console.error('Error assigning user to application:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to assign user to application',
            error: error.message
        });
    }
});

// Update user assignment
app.put('/api/app-users/:applicationId/:userId', adminAccess, csrfProtection, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        const userId = parseInt(req.params.userId);
        
        if (isNaN(applicationId) || isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID or user ID'
            });
        }
        
        const {
            app_role,
            status,
            start_date,
            end_date,
            track_user
        } = req.body;
        
        const [result] = await pool.execute(`
            UPDATE sa_app_user 
            SET 
                app_role = ?,
                status = ?,
                start_date = ?,
                end_date = ?,
                track_user = ?,
                date_updated = CURRENT_TIMESTAMP
            WHERE application_id = ? AND user_id = ?
        `, [
            app_role || null,
            status || 'Inactive',
            start_date || null,
            end_date || null,
            track_user || 'No',
            applicationId,
            userId
        ]);
        
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
        console.error('Error updating user assignment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user assignment',
            error: error.message
        });
    }
});

// Remove user from application  
app.delete('/api/app-users/:applicationId/:userId', adminAccess, csrfProtection, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        const userId = parseInt(req.params.userId);
        
        if (isNaN(applicationId) || isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID or user ID'
            });
        }
        
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
            message: 'User removed from application successfully'
        });
        
    } catch (error) {
        console.error('Error removing user from application:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to remove user from application',
            error: error.message
        });
    }
});

// Verify admin access endpoint
app.post('/api/auth/verify-admin', csrfProtection, userAccess, (req, res) => {
    res.json({
        success: true,
        user: {
            username: 'admin',
            role: 'Admin'
        }
    });
});

// Get security questions for password reset
app.post('/api/auth/security-questions', csrfProtection, async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required'
            });
        }
        
        // Find user by username or email
        const [users] = await pool.execute(
            'SELECT security_question_1, security_question_2 FROM sa_users WHERE username = ? OR email = ?',
            [username, username]
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
                question1: user.security_question_1 || 'No security question set',
                question2: user.security_question_2 || 'No security question set'
            }
        });
        
    } catch (error) {
        console.error('Error fetching security questions:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch security questions',
            error: error.message
        });
    }
});

// Reset password using security questions
app.post('/api/auth/reset-password', csrfProtection, async (req, res) => {
    try {
        const { username, answer1, answer2, newPassword } = req.body;
        
        if (!username || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Username and new password are required'
            });
        }
        
        if (!answer1 && !answer2) {
            return res.status(400).json({
                success: false,
                message: 'At least one security answer is required'
            });
        }
        
        // Find user by username or email
        const [users] = await pool.execute(
            'SELECT user_id, security_answer_1_hash, security_answer_2_hash FROM sa_users WHERE username = ? OR email = ?',
            [username, username]
        );
        
        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const user = users[0];
        let isValid = false;
        
        // Check security answers
        if (answer1 && user.security_answer_1_hash) {
            isValid = await verifyPassword(answer1.trim(), user.security_answer_1_hash);
        }
        
        if (!isValid && answer2 && user.security_answer_2_hash) {
            isValid = await verifyPassword(answer2.trim(), user.security_answer_2_hash);
        }
        
        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid security answer'
            });
        }
        
        // Hash new password
        const passwordHash = await hashPassword(newPassword);
        
        // Update password
        await pool.execute(
            'UPDATE sa_users SET master_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
            [passwordHash, user.user_id]
        );
        
        res.json({
            success: true,
            message: 'Password reset successfully'
        });
        
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password',
            error: error.message
        });
    }
});

// Login endpoint (for authentication)
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
            'SELECT * FROM sa_users WHERE username = ? OR email = ?',
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
        console.log(`   Account status: ${user.account_status}`);
        console.log(`   Has master_password_hash: ${!!user.master_password_hash}`);
        console.log(`   Hash length: ${user.master_password_hash ? user.master_password_hash.length : 0}`);
        
        // Verify password
        const passwordValid = await verifyPassword(password, user.master_password_hash);
        console.log(`   Password valid: ${passwordValid}`);
        
        if (!passwordValid) {
            console.log(`❌ Invalid password for user: ${username}`);
            // Don't reset rate limit on failed password
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
        
        // Update last login timestamp
        await pool.execute(
            'UPDATE sa_users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
            [user.user_id]
        );
        
        console.log(`✅ Login successful for user: ${username}`);
        
        // Create session for all users
        const sessionId = crypto.randomBytes(32).toString('hex');
        activeSessions.set(sessionId, {
            userId: user.user_id,
            username: user.username,
            role: user.role,
            createdAt: new Date()
        });
        
        // Generate CSRF token
        const csrfToken = generateCSRFToken();
        csrfTokens.set(sessionId, csrfToken);
        
        // Return user info (excluding sensitive data)
        const { master_password_hash, security_answer_1_hash, security_answer_2_hash, ...userInfo } = user;
        
        res.json({
            success: true,
            message: 'Login successful',
            data: {
                user: userInfo,
                sessionId: sessionId,
                csrfToken: csrfToken
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

// Get all tracking records
app.get('/api/track-user', adminAccess, async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT 
                t.track_id,
                t.user_id,
                t.application_id,
                t.event_date,
                t.computer_name,
                t.computer_MAC,
                t.computer_ip,
                a.application_name,
                u.username,
                u.first_name,
                u.last_name
            FROM sa_tracking_user t
            JOIN sa_applications a ON t.application_id = a.application_id
            JOIN sa_users u ON t.user_id = u.user_id
            ORDER BY t.event_date DESC
        `);
        
        res.json({
            success: true,
            data: rows
        });
        
    } catch (error) {
        console.error('Error fetching tracking records:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch tracking records',
            error: error.message
        });
    }
});

// Create tracking record
app.post('/api/track-user', userAccess, csrfProtection, async (req, res) => {
    try {
        const {
            user_id,
            application_id,
            event_date,
            computer_name,
            computer_MAC,
            computer_ip
        } = req.body;
        
        if (!user_id || !application_id) {
            return res.status(400).json({
                success: false,
                message: 'User ID and Application ID are required'
            });
        }
        
        // Convert ISO string to MySQL datetime format
        let mysqlDateTime = null;
        if (event_date) {
            const date = new Date(event_date);
            mysqlDateTime = date.toISOString().slice(0, 19).replace('T', ' ');
        }
        
        const [result] = await pool.execute(`
            INSERT INTO sa_tracking_user (
                user_id,
                application_id,
                event_date,
                computer_name,
                computer_MAC,
                computer_ip
            ) VALUES (?, ?, ?, ?, ?, ?)
        `, [
            user_id,
            application_id,
            mysqlDateTime,
            computer_name || null,
            computer_MAC || null,
            computer_ip || null
        ]);
        
        res.status(201).json({
            success: true,
            message: 'Tracking record created successfully',
            data: {
                track_id: result.insertId
            }
        });
        
    } catch (error) {
        console.error('Error creating tracking record:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create tracking record',
            error: error.message
        });
    }
});

// Get tracking records for specific user
app.get('/api/track-user/user/:userId', adminAccess, async (req, res) => {
    try {
        const userId = parseInt(req.params.userId);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                t.track_id,
                t.application_id,
                t.event_date,
                t.computer_name,
                t.computer_MAC,
                t.computer_ip,
                a.application_name
            FROM sa_tracking_user t
            JOIN sa_applications a ON t.application_id = a.application_id
            WHERE t.user_id = ?
            ORDER BY t.event_date DESC
        `, [userId]);
        
        res.json({
            success: true,
            data: rows
        });
        
    } catch (error) {
        console.error('Error fetching user tracking records:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user tracking records',
            error: error.message
        });
    }
});

// Get tracking records for specific application
app.get('/api/track-user/application/:applicationId', adminAccess, async (req, res) => {
    try {
        const applicationId = parseInt(req.params.applicationId);
        
        if (isNaN(applicationId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid application ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                t.track_id,
                t.user_id,
                t.event_date,
                t.computer_name,
                t.computer_MAC,
                t.computer_ip,
                u.username,
                u.first_name,
                u.last_name
            FROM sa_tracking_user t
            JOIN sa_users u ON t.user_id = u.user_id
            WHERE t.application_id = ?
            ORDER BY t.event_date DESC
        `, [applicationId]);
        
        res.json({
            success: true,
            data: rows
        });
        
    } catch (error) {
        console.error('Error fetching application tracking records:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch application tracking records',
            error: error.message
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

// Session cleanup - run every 30 minutes
setInterval(() => {
    const now = Date.now();
    const expiredSessions = [];
    
    for (const [sessionId, session] of activeSessions.entries()) {
        if (now - session.createdAt.getTime() > 3600000) { // 1 hour
            expiredSessions.push(sessionId);
        }
    }
    
    expiredSessions.forEach(sessionId => {
        activeSessions.delete(sessionId);
        csrfTokens.delete(sessionId);
    });
    
    if (expiredSessions.length > 0) {
        console.log(`🧹 Cleaned up ${expiredSessions.length} expired sessions`);
    }
}, 30 * 60 * 1000);

// Start server
async function startServer() {
    try {
        await initDatabase();
        
        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
            console.log(`📊 Admin page: http://localhost:${PORT}/admin-users.html`);
            console.log(`🏥 Health check: http://localhost:${PORT}/health`);
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down server...');
    if (pool) {
        await pool.end();
        console.log('✅ Database connections closed');
    }
    process.exit(0);
});

// Start the server
startServer();

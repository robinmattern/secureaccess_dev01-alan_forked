/**
 * Server-Side Security Middleware
 * Comprehensive security features for authentication system
 */

const crypto = require('crypto');
const validator = require('validator');

// Token signature secret (should be in .env)
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');

// Account lockout tracking
const accountLockouts = new Map();
const failedAttempts = new Map();
const MAX_LOCKOUT_ENTRIES = 10000;

// Audit log storage
const auditLogs = [];

// Periodic cleanup of expired lockouts
let cleanupInterval = null;

function startCleanupInterval() {
    if (cleanupInterval) return;
    
    cleanupInterval = setInterval(() => {
        const now = Date.now();
        
        // Only iterate if there are entries
        if (accountLockouts.size === 0) return;
        
        // Clean expired lockouts
        for (const [username, lockout] of accountLockouts.entries()) {
            if (now >= lockout.until) {
                accountLockouts.delete(username);
                failedAttempts.delete(username);
            }
        }
        
        // Only sort and trim if over limit
        if (accountLockouts.size > MAX_LOCKOUT_ENTRIES) {
            const entries = Array.from(accountLockouts.entries());
            entries.sort((a, b) => a[1].until - b[1].until);
            const toDelete = entries.slice(0, accountLockouts.size - MAX_LOCKOUT_ENTRIES);
            toDelete.forEach(([username]) => {
                accountLockouts.delete(username);
                failedAttempts.delete(username);
            });
        }
    }, 5 * 60 * 1000);
}

// Start cleanup on first use
startCleanupInterval();

/**
 * Sign auth token with HMAC
 */
function signAuthToken(tokenData) {
    const payload = JSON.stringify(tokenData);
    const signature = crypto
        .createHmac('sha256', TOKEN_SECRET)
        .update(payload)
        .digest('hex');
    
    return `${Buffer.from(payload).toString('base64')}.${signature}`;
}

/**
 * Verify auth token signature
 */
function verifyAuthToken(token) {
    try {
        const [payloadB64, signature] = token.split('.');
        if (!payloadB64 || !signature) {
            return { valid: false, reason: 'Invalid token format' };
        }
        
        if (payloadB64.length > 4096) {
            return { valid: false, reason: 'Token too large' };
        }
        
        let payload;
        try {
            payload = Buffer.from(payloadB64, 'base64').toString('utf8');
        } catch (e) {
            return { valid: false, reason: 'Invalid token encoding' };
        }
        
        if (payload.length > 8192) {
            return { valid: false, reason: 'Payload too large' };
        }
        const expectedSignature = crypto
            .createHmac('sha256', TOKEN_SECRET)
            .update(payload)
            .digest('hex');
        
        if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
            return { valid: false, reason: 'Invalid signature' };
        }
        
        let data;
        try {
            data = JSON.parse(payload, (key, value) => {
                if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                    return undefined;
                }
                return value;
            });
        } catch (e) {
            return { valid: false, reason: 'Invalid token data' };
        }
        
        if (!data || typeof data !== 'object' || Array.isArray(data)) {
            return { valid: false, reason: 'Invalid token structure' };
        }
        
        // Prevent prototype pollution
        if (data.__proto__ || data.constructor || data.prototype) {
            return { valid: false, reason: 'Invalid token properties' };
        }
        
        // Check expiration
        if (data.exp && Date.now() > data.exp) {
            return { valid: false, reason: 'Token expired' };
        }
        
        // Sanitize data
        if (data.username) data.username = validator.escape(data.username);
        if (data.email) data.email = validator.escape(data.email);
        
        return { valid: true, data };
    } catch (error) {
        return { valid: false, reason: 'Token verification failed' };
    }
}

/**
 * Middleware to verify auth token in request
 */
function verifyAuthTokenMiddleware(req, res, next) {
    const token = req.query.auth_token || req.body.auth_token;
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Auth token required'
        });
    }
    
    const result = verifyAuthToken(token);
    
    if (!result.valid) {
        auditLog('TOKEN_VERIFICATION_FAILED', { reason: result.reason, ip: req.ip });
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }
    
    req.authData = result.data;
    next();
}

/**
 * Account lockout check
 */
function checkAccountLockout(username) {
    const lockoutData = accountLockouts.get(username);
    
    if (lockoutData && Date.now() < lockoutData.until) {
        return {
            locked: true,
            remainingTime: Math.ceil((lockoutData.until - Date.now()) / 1000 / 60)
        };
    }
    
    if (lockoutData && Date.now() >= lockoutData.until) {
        accountLockouts.delete(username);
        failedAttempts.delete(username);
    }
    
    return { locked: false };
}

/**
 * Record failed login attempt
 */
function recordFailedAttempt(username, ip) {
    const attempts = failedAttempts.get(username) || [];
    const now = Date.now();
    
    // Remove attempts older than 15 minutes
    const recentAttempts = attempts.filter(time => now - time < 15 * 60 * 1000);
    recentAttempts.push(now);
    
    failedAttempts.set(username, recentAttempts);
    
    // Lock account after 5 failed attempts
    if (recentAttempts.length >= 5) {
        const lockoutUntil = now + (30 * 60 * 1000); // 30 minutes
        accountLockouts.set(username, { until: lockoutUntil });
        
        auditLog('ACCOUNT_LOCKED', { username, ip, attempts: recentAttempts.length });
        
        return true;
    }
    
    auditLog('FAILED_LOGIN', { username, ip, attempts: recentAttempts.length });
    return false;
}

/**
 * Clear failed attempts on successful login
 */
function clearFailedAttempts(username) {
    failedAttempts.delete(username);
    accountLockouts.delete(username);
}

/**
 * Middleware for account lockout
 */
function accountLockoutMiddleware(req, res, next) {
    const username = req.body.username;
    
    if (!username) {
        return next();
    }
    
    const lockout = checkAccountLockout(username);
    
    if (lockout.locked) {
        return res.status(423).json({
            success: false,
            message: `Account locked. Try again in ${lockout.remainingTime} minutes.`
        });
    }
    
    next();
}

/**
 * Input sanitization middleware
 */
function sanitizeInputs(req, res, next) {
    if (req.body) {
        for (const key in req.body) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = validator.escape(req.body[key]);
            }
        }
    }
    
    if (req.query) {
        for (const key in req.query) {
            if (typeof req.query[key] === 'string') {
                req.query[key] = validator.escape(req.query[key]);
            }
        }
    }
    
    next();
}

/**
 * Password strength validation
 */
function validatePasswordStrength(password) {
    const errors = [];
    
    if (!validator.isLength(password, { min: 12, max: 128 })) {
        errors.push('Password must be 12-128 characters');
    }
    
    if (!validator.isStrongPassword(password, {
        minLength: 12,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
    })) {
        errors.push('Password must contain uppercase, lowercase, number, and special character');
    }
    
    return {
        valid: errors.length === 0,
        errors
    };
}

/**
 * Audit logging
 */
function auditLog(event, data = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        event,
        ...data
    };
    
    auditLogs.push(logEntry);
    console.log(`🔒 AUDIT: ${event}`, data);
    
    // Keep only last 1000 logs in memory
    if (auditLogs.length > 1000) {
        auditLogs.shift();
    }
}

/**
 * Get audit logs (admin only)
 */
function getAuditLogs(limit = 100) {
    return auditLogs.slice(-limit);
}

/**
 * Security headers middleware
 */
function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    next();
}

module.exports = {
    signAuthToken,
    verifyAuthToken,
    verifyAuthTokenMiddleware,
    checkAccountLockout,
    recordFailedAttempt,
    clearFailedAttempts,
    accountLockoutMiddleware,
    sanitizeInputs,
    validatePasswordStrength,
    auditLog,
    getAuditLogs,
    securityHeaders
};

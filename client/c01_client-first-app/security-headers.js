/**
 * Security Headers and HTTPS Enforcement
 */

// Enforce HTTPS in production
if (window.location.protocol === 'http:' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
    window.location.href = window.location.href.replace('http:', 'https:');
}

// Set Content Security Policy via meta tag if not set by server
if (!document.querySelector('meta[http-equiv="Content-Security-Policy"]')) {
    const apiUrl = window.FVARS?.SECURE_API_URL || window.location.origin;
    const apiOrigin = new URL(apiUrl).origin;
    
    const cspMeta = document.createElement('meta');
    cspMeta.httpEquiv = 'Content-Security-Policy';
    cspMeta.content = `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ${apiOrigin};`;
    document.head.appendChild(cspMeta);
}

// Prevent clickjacking
if (window.self !== window.top) {
    window.top.location = window.self.location;
}

// Input sanitization helper
window.sanitizeInput = function(input) {
    if (typeof input !== 'string') return input;
    
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
};

// Password strength validator
window.validatePasswordStrength = function(password) {
    const errors = [];
    
    if (password.length < 12) {
        errors.push('Password must be at least 12 characters');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain lowercase letters');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain uppercase letters');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain numbers');
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain special characters');
    }
    
    return {
        valid: errors.length === 0,
        errors: errors
    };
};

// Token revocation manager
window.TokenRevocation = {
    revokedTokens: new Set(),
    isDirty: false,
    saveTimeout: null,
    
    revokeToken(token) {
        this.revokedTokens.add(token);
        this.isDirty = true;
        this.scheduleSave();
    },
    
    scheduleSave() {
        // Debounce saves to sessionStorage
        if (this.saveTimeout) {
            clearTimeout(this.saveTimeout);
        }
        this.saveTimeout = setTimeout(() => {
            if (this.isDirty) {
                sessionStorage.setItem('revoked_tokens', JSON.stringify([...this.revokedTokens]));
                this.isDirty = false;
            }
            this.saveTimeout = null;
        }, 100);
    },
    
    isRevoked(token) {
        if (this.revokedTokens.size === 0) {
            const stored = sessionStorage.getItem('revoked_tokens');
            if (stored) {
                this.revokedTokens = new Set(JSON.parse(stored));
            }
        }
        return this.revokedTokens.has(token);
    },
    
    clearRevoked() {
        this.revokedTokens.clear();
        this.isDirty = false;
        if (this.saveTimeout) {
            clearTimeout(this.saveTimeout);
            this.saveTimeout = null;
        }
        sessionStorage.removeItem('revoked_tokens');
    }
};

// Account lockout manager
window.AccountLockout = {
    attempts: {},
    lockouts: {},
    
    recordFailedAttempt(username) {
        const key = `lockout_${username}`;
        const now = Date.now();
        const cutoff = now - (15 * 60 * 1000);
        
        if (!this.attempts[username]) {
            this.attempts[username] = [];
        }
        
        // Remove attempts older than 15 minutes
        this.attempts[username] = this.attempts[username].filter(time => time > cutoff);
        this.attempts[username].push(now);
        
        // Lock account after 5 failed attempts
        if (this.attempts[username].length >= 5) {
            this.lockouts[username] = now + (30 * 60 * 1000); // 30 minute lockout
            localStorage.setItem(key, this.lockouts[username].toString());
            return true;
        }
        
        return false;
    },
    
    isLocked(username) {
        const key = `lockout_${username}`;
        const lockoutTime = this.lockouts[username] || parseInt(localStorage.getItem(key) || '0');
        
        if (lockoutTime && Date.now() < lockoutTime) {
            return true;
        }
        
        // Clear expired lockout
        if (lockoutTime) {
            delete this.lockouts[username];
            localStorage.removeItem(key);
        }
        
        return false;
    },
    
    clearAttempts(username) {
        delete this.attempts[username];
        delete this.lockouts[username];
        localStorage.removeItem(`lockout_${username}`);
    }
};

// Rate limiting helper (client-side)
window.RateLimiter = {
    attempts: {},
    
    checkLimit(key, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
        const now = Date.now();
        
        if (!this.attempts[key]) {
            this.attempts[key] = [];
        }
        
        // Remove old attempts outside the window
        this.attempts[key] = this.attempts[key].filter(time => now - time < windowMs);
        
        if (this.attempts[key].length >= maxAttempts) {
            return false;
        }
        
        this.attempts[key].push(now);
        return true;
    },
    
    reset(key) {
        delete this.attempts[key];
    }
};

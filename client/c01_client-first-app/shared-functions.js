// Shared functions for secure access application

// Client-side error handler
function handleClientError(error, context) {
    const errorMessage = error?.message || 'Unknown error';
    const timestamp = new Date().toISOString();
    console.error(`❌ [${timestamp}] Error in ${context}:`, errorMessage);
    if (error?.stack) {
        console.error('Stack trace:', error.stack);
    }
}

// Configuration management
const ConfigManager = {
    config: null,
    
    async getConfig() {
        if (this.config) {
            return this.config;
        }
        if (!window.FVARS) {
            console.error('No client _config.js file found');
            throw new Error('No client _config.js file found');
        }
        this.config = window.FVARS;
        this.config.port = window.FVARS.SECURE_API_URL.match(/:([0-9]+)\/?/)?.slice(1,2)[0] ?? '';
        this.config.apiBaseUrl = window.FVARS.SECURE_API_URL;
        return this.config;
    }
};

// CSRF token management - Double-Submit Cookie Pattern
const CSRFManager = {
    token: null,
    
    // Get CSRF token from cookie
    getTokenFromCookie() {
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === '_csrf') {
                return decodeURIComponent(value);
            }
        }
        return null;
    },
    
    async getToken() {
        // First try to get token from cookie
        const cookieToken = this.getTokenFromCookie();
        if (cookieToken) {
            this.token = cookieToken;
            return this.token;
        }
        
        // If no cookie token, fetch new one from server
        try {
            const config = await ConfigManager.getConfig();
            const response = await fetch(`${config.apiBaseUrl.replace('/api', '')}/api/csrf-token`, { 
                credentials: 'include',
                method: 'GET'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            this.token = data.csrfToken;
            
            return this.token;
        } catch (error) {
            handleClientError(error, 'get CSRF token');
            return null;
        }
    },
    
    clearToken() {
        this.token = null;
        // Clear cookie
        document.cookie = '_csrf=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    }
};

// Auth token management - Using HTTP-only cookies
const AuthManager = {
    // HTTP-only cookies are handled server-side
    // No client-side token storage needed
    
    setToken(token) {
        // Tokens are set as HTTP-only cookies by server
        console.log('Token management handled by HTTP-only cookies');
    },

    getToken() {
        // Cannot access HTTP-only cookies from JavaScript
        return null;
    },

    clearToken() {
        // Logout handled by server clearing cookies
        console.log('Token clearing handled by server');
    },

    parseAndStoreUserInfo(token) {
        // User info obtained from server API calls
        return null;
    },

    getUserInfo() {
        // User info obtained from server API calls
        return null;
    },

    isLoggedIn() {
        // Authentication status checked via server API
        return false;
    }
};

// Global web page redirect function
window.SA_GoToWebPage = function(webpage) {
    if (!webpage || typeof webpage !== 'string') {
        throw new Error('Invalid webpage URL');
    }
    
    try {
        const url = new URL(webpage, window.location.origin);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            throw new Error('Invalid URL protocol');
        }
        
        // Validate against trusted domains
        const trustedDomains = [
            'localhost',
            '127.0.0.1',
            'secureaccess247.com'
        ];
        const isTrusted = trustedDomains.some(domain => 
            url.hostname === domain || url.hostname.endsWith('.' + domain)
        );
        
        if (!isTrusted) {
            throw new Error('URL domain is not in the trusted list');
        }
        
        window.location.href = url.href;
    } catch (e) {
        handleClientError(e, 'navigate to webpage');
        throw new Error('Invalid webpage URL');
    }
};

// Global function to initialize a protected page
window.SA_InitializePage = function() {
    // Authentication handled by server-side verification
    // Pages should verify auth via API calls to server
    return true;
};

// Shared PKCE token validation function
window.validateAuthToken = function(token) {
    try {
        // Check if token is revoked
        if (window.TokenRevocation && window.TokenRevocation.isRevoked(token)) {
            return { valid: false, reason: 'Token has been revoked' };
        }
        
        const decoded = PKCEUtils.decodePKCEToken(token);
        if (!decoded.userData) {
            return { valid: false, reason: 'Invalid token format' };
        }
        
        // Check expiration
        if (decoded.userData.exp && Date.now() > decoded.userData.exp) {
            return { valid: false, reason: 'Token expired' };
        }
        
        // Validate required fields
        if (!decoded.userData.username || !decoded.userData.email) {
            return { valid: false, reason: 'Missing required fields' };
        }
        
        // Sanitize user data
        decoded.userData.username = window.sanitizeInput(decoded.userData.username);
        decoded.userData.email = window.sanitizeInput(decoded.userData.email);
        
        return { valid: true, userData: decoded.userData };
    } catch (error) {
        handleClientError(error, 'validate auth token');
        return { valid: false, reason: 'Token validation failed' };
    }
};

// Shared PKCE token creation function
window.createPKCEToken = function(currentUser, accessResult = null) {
    if (!currentUser) {
        throw new Error('Current user is required for PKCE token creation');
    }
    
    try {
        // Sanitize user data before encoding
        const tokenData = {
            username: window.sanitizeInput(currentUser.username),
            email: window.sanitizeInput(currentUser.email),
            app_role: accessResult?.app_role || 'NULL',
            exp: Date.now() + (10 * 60 * 1000), // 10 minute expiration
            iat: Date.now()
        };
        
        return PKCEUtils.generateCodeVerifier(tokenData);
    } catch (error) {
        handleClientError(error, 'create PKCE token');
        throw new Error('Failed to create PKCE token');
    }
};

// Export for use in other scripts
window.AuthManager = AuthManager;
window.CSRFManager = CSRFManager;
window.ConfigManager = ConfigManager;

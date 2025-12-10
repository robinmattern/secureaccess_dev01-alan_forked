// Shared functions for secure access application

// Configuration management
const ConfigManager = {
    config: null,
    
    async getConfig() {
        if (this.config) {
            return this.config;
        }
       if (!window.FVARS) {                                                             // .(51013.04.8 RAM Use formR Vars Beg)
            console.error('  No client _config.js file found:', error);
            throw new Error('No client _config.js file found');
       } else {
            this.config = window.FVARS;
            this.config.port       = window.FVARS.SECURE_API_URL.match( /:([0-9]+)\/?/)?.slice(1,2)[0] ?? ''      // .(51108.02.1 RAM Was SECURE_HOST).(51108.02.1 RAM Was SECURE_PATH).(51013.04.9 RAM for SecureAccess client)    
            this.config.apiBaseUrl = window.FVARS.SECURE_API_URL
     return this.config;
            }                                                                           // .(51013.04.8 End)
// ----------------------------------------------------------------------------

        // Since client files are served by the same server, use same origin
        try {
//          const response = await fetch(`${window.location.origin}/config`);
            if (response.ok) {
                this.config = await response.json();
                return this.config;
            }
        } catch (error) {
            console.error('Failed to get server config:', error);
        }
        
        // Fallback to current origin
        this.config = {
            port: window.location.port || 3005,
//          apiBaseUrl: `${window.location.origin}/api`
        };
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
            console.error('Failed to get CSRF token:', error);
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
    window.location.href = webpage;
};

// Global function to initialize a protected page
window.SA_InitializePage = function() {
    // Authentication handled by server-side verification
    // Pages should verify auth via API calls to server
    return true;
};

// Shared PKCE token creation function
window.createPKCEToken = function(currentUser, accessResult = null) {
    if (!currentUser) {
        throw new Error('Current user is required for PKCE token creation');
    }
    return PKCEUtils.generateCodeVerifier({
        username: currentUser.username,
        email: currentUser.email,
        app_role: accessResult?.app_role || 'NULL'
    });
};

// Export for use in other scripts
window.AuthManager = AuthManager;
window.CSRFManager = CSRFManager;
window.ConfigManager = ConfigManager;

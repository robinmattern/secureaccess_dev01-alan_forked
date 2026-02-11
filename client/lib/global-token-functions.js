// Client-side JWT token helper functions

// Check if user has JWT token in cookie
function hasAuthToken() {
    const authToken = document.cookie.split(';').find(row => 
        row.trim().startsWith('auth_token=')
    );
    return !!authToken;
}

// Get token from cookie
function getAuthToken() {
    const cookie = document.cookie.split(';').find(row => 
        row.trim().startsWith('auth_token=')
    );
    return cookie ? cookie.split('=')[1] : null;
}

// Clear authentication token
function clearAuthToken() {
    document.cookie = 'auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
}

// Make authenticated API request
async function authenticatedFetch(url, options = {}) {
    // Validate URL to prevent SSRF
    if (!url || typeof url !== 'string') {
        throw new Error('Invalid URL');
    }
    
    try {
        const urlObj = new URL(url, window.location.origin);
        
        // Only allow same-origin requests
        if (urlObj.origin !== window.location.origin) {
            throw new Error('Cross-origin requests not allowed');
        }
        
        // Prevent access to internal networks
        const isInternalIP = (hostname) => {
            return hostname === 'localhost' || 
                   hostname === '127.0.0.1' || 
                   hostname.startsWith('192.168.') || 
                   hostname.startsWith('10.') || 
                   hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
        };
        
        if (isInternalIP(urlObj.hostname) && urlObj.hostname !== window.location.hostname) {
            throw new Error('Access to internal networks is not allowed');
        }
        
        const defaultOptions = {
            credentials: 'include',
            redirect: 'manual',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        };
        
        const response = await fetch(urlObj.href, { ...defaultOptions, ...options });
        
        // Reject redirects
        if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
            throw new Error('Redirects are not allowed');
        }
        
        return response;
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}
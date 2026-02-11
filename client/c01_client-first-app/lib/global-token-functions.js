// Client-side JWT token helper functions

// Check if user has valid JWT token
function hasValidToken() {
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
async function authenticatedFetch(endpoint, options = {}) {
    const baseUrl = new URL(window.FVARS.SERVER_API_URL);
    const url = new URL(endpoint, baseUrl);
    
    if (url.origin !== baseUrl.origin || url.hostname !== baseUrl.hostname) {
        throw new Error('Invalid API endpoint');
    }
    
    const defaultOptions = {
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        }
    };
    
    return fetch(url.href, { ...defaultOptions, ...options });
}
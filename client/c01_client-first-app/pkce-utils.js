/**
 * Production-ready PKCE (Proof Key for Code Exchange) implementation
 * RFC 7636 compliant
 */

class PKCEUtils {
    /**
     * Base64 URL encode without padding
     */
    static base64URLEncode(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Generate cryptographically secure random string with optional user data
     */
    static generateCodeVerifier(userData = null) {
        // RFC 7636: code_verifier must be 43-128 characters
        const array = new Uint8Array(32); // 32 bytes = 43 chars when base64url encoded
        crypto.getRandomValues(array);
        const baseToken = this.base64URLEncode(array);
        
        if (userData) {
            const userInfo = btoa(JSON.stringify(userData))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
            return `${baseToken}.${userInfo}`;
        }
        return baseToken;
    }

    /**
     * Generate code challenge from verifier using SHA256
     */
    static async generateCodeChallenge(codeVerifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return this.base64URLEncode(digest);
    }

    /**
     * Generate complete PKCE pair
     */
    static async generatePKCE() {
        const codeVerifier = this.generateCodeVerifier();
        const codeChallenge = await this.generateCodeChallenge(codeVerifier);
        
        return {
            codeVerifier,
            codeChallenge,
            codeChallengeMethod: 'S256'
        };
    }

    /**
     * Generate secure state parameter for CSRF protection
     */
    static generateState() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return this.base64URLEncode(array);
    }

    /**
     * Store PKCE session data securely with user data
     */
    static storePKCESession(sessionData, userData = {}) {
        const sessionId = this.generateState();
        const expiresAt = Date.now() + (10 * 60 * 1000); // 10 minutes
        
        const session = {
            ...sessionData,
            userData, // Store username, email, etc.
            expiresAt,
            timestamp: Date.now()
        };
        
        sessionStorage.setItem(`pkce_${sessionId}`, JSON.stringify(session));
        return sessionId;
    }

    /**
     * Retrieve and validate PKCE session
     */
    static getPKCESession(sessionId) {
        const sessionKey = `pkce_${sessionId}`;
        const sessionData = sessionStorage.getItem(sessionKey);
        
        if (!sessionData) {
            return null;
        }
        
        try {
            const session = JSON.parse(sessionData);
            
            // Check expiration
            if (Date.now() > session.expiresAt) {
                sessionStorage.removeItem(sessionKey);
                return null;
            }
            
            return session;
        } catch (error) {
            console.error('Error retrieving PKCE session:', error?.message || 'Unknown error');
            sessionStorage.removeItem(sessionKey);
            return null;
        }
    }

    /**
     * Clear PKCE session
     */
    static clearPKCESession(sessionId) {
        sessionStorage.removeItem(`pkce_${sessionId}`);
    }

    /**
     * Decode PKCE token to extract user data
     */
    static decodePKCEToken(pkceToken) {
        try {
            const parts = pkceToken.split('.');
            if (parts.length !== 2) {
                return { token: pkceToken, userData: null };
            }
            
            const [baseToken, encodedUserData] = parts;
            const decodedUserData = JSON.parse(atob(encodedUserData.replace(/-/g, '+').replace(/_/g, '/')));
            
            return {
                token: baseToken,
                userData: decodedUserData
            };
        } catch (error) {
            console.error('Error decoding user data:', error?.message || 'Unknown error');
            return { token: pkceToken, userData: null };
        }
    }

    /**
     * Validate PKCE parameters
     */
    static validatePKCE(codeVerifier, codeChallenge) {
        if (!codeVerifier || !codeChallenge) {
            return false;
        }
        
        // RFC 7636: code_verifier length check
        if (codeVerifier.length < 43 || codeVerifier.length > 128) {
            return false;
        }
        
        // Verify code_verifier matches challenge
        return this.generateCodeChallenge(codeVerifier)
            .then(challenge => challenge === codeChallenge)
            .catch(() => false);
    }
}

// Export for use in other files
window.PKCEUtils = PKCEUtils;
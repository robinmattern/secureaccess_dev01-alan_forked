// Global authentication and user data management
class GlobalAuth {
    static _gMemberId = null;
    static _gRole = null;
    static _gRoleId = null;
    static _gMemberName = null;
    
    // Getter functions
    static getMemberId() {
        return this._gMemberId;
    }
    
    static getRole() {
        return this._gRole;
    }
    
    static getRoleId() {
        return this._gRoleId;
    }
    
    static getMemberName() {
        return this._gMemberName;
    }
    
    // Setter functions
    static setMemberId(id) {
        this._gMemberId = id;
        window.gMemberId = id; // Keep window global for compatibility
    }
    
    static setRole(role) {
        this._gRole = role;
        window.gRole = role; // Keep window global for compatibility
    }
    
    static setRoleId(roleId) {
        this._gRoleId = roleId;
        window.gRoleId = roleId; // Keep window global for compatibility
    }
    
    static setMemberName(name) {
        this._gMemberName = name;
        window.gMemberName = name; // Keep window global for compatibility
    }
    
    // Initialize authentication from URL or parent window
    static async initialize() {
        // Try to get from parent window first
        if (window.parent && window.parent.gMemberId) {
            this.setMemberId(window.parent.gMemberId);
            this.setRole(window.parent.gRole);
            this.setRoleId(window.parent.gRoleId);
            this.setMemberName(window.parent.gMemberName);
            console.log('Auth initialized from parent window');
            
            // If role is missing, load it from database
            if (!this._gRole && this._gMemberId) {
                await this.loadRoleByMemberId(this._gMemberId);
            }
            return;
        }
        
        // Try to get from URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const email = urlParams.get('email');
        
        if (email) {
            await this.loadUserByEmail(email);
        } else {
            // Default for testing
            this.setMemberId(1);
            this.setRole('Admin');
            this.setRoleId(1);
            this.setMemberName('Test Admin');
            console.log('Auth initialized with default values');
        }
    }
    
    // Load user data by email
    static async loadUserByEmail(email) {
        try {
            const endpoint = `/user_by_email?email=${encodeURIComponent(email)}`;
            if (!endpoint.startsWith('/')) {
                throw new Error('Invalid API endpoint');
            }
            
            if (endpoint.includes('..') || endpoint.includes('//') || endpoint.includes('\\')) {
                throw new Error('Invalid API endpoint');
            }
            
            if (endpoint.includes('%25') || endpoint.includes('@')) {
                throw new Error('Invalid API endpoint');
            }
            
            const baseUrl = new URL(window.FVARS.SERVER_API_URL);
            const url = new URL(endpoint, baseUrl);
            
            if (url.origin !== baseUrl.origin || url.hostname !== baseUrl.hostname) {
                throw new Error('Invalid API endpoint');
            }
            
            const isInternalIP = (hostname) => {
                return hostname === 'localhost' || 
                       hostname === '127.0.0.1' || 
                       hostname.startsWith('192.168.') || 
                       hostname.startsWith('10.') || 
                       hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
            };
            
            if (isInternalIP(url.hostname) && !isInternalIP(baseUrl.hostname)) {
                throw new Error('Access to internal networks is not allowed');
            }
            
            const response = await fetch(url.href, { redirect: 'manual' });
            
            if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
                throw new Error('Redirects are not allowed');
            }
            
            const data = await response.json();
            
            const member = data?.user_by_email?.[0] || data?.members?.[0] || (Array.isArray(data) ? data[0] : null);
            
            if (member && (member.MemberNo || member.Id)) {
                this.setMemberId(member.MemberNo || member.Id);
                this.setMemberName(member.UserName || member.FullName || 'Member');
                this.setRoleId(member.RoleId || 1);
                
                // Fetch role name
                await this.loadRoleName();
                console.log('Auth initialized from email lookup');
            }
        } catch (error) {
            const errorMessage = error && error.message ? error.message : 'Unknown error';
            console.error('Error loading user by email:', errorMessage);
        }
    }
    
    // Load role by member ID
    static async loadRoleByMemberId(memberId) {
        try {
            const endpoint = `/members?id=${memberId}`;
            if (!endpoint.startsWith('/') || endpoint.includes('..') || endpoint.includes('//') || endpoint.includes('\\')) {
                throw new Error('Invalid API endpoint');
            }
            
            const baseUrl = new URL(window.FVARS.SERVER_API_URL);
            const url = new URL(endpoint, baseUrl);
            
            if (url.origin !== baseUrl.origin || url.hostname !== baseUrl.hostname) {
                throw new Error('Invalid API endpoint');
            }
            
            const response = await fetch(url.href, { redirect: 'manual' });
            
            if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
                throw new Error('Redirects are not allowed');
            }
            const data = await response.json();
            
            if (data.members && data.members.length > 0) {
                const member = data.members[0];
                this.setRoleId(member.RoleId || 1);
                await this.loadRoleName();
                console.log('Role loaded by member ID:', this._gRole);
            }
        } catch (error) {
            const errorMessage = error && error.message ? error.message : 'Unknown error';
            console.error('Error loading role by member ID:', errorMessage);
            this.setRole('Member');
        }
    }
    
    // Load role name from role ID
    static async loadRoleName() {
        try {
            const endpoint = '/webpage_roles_view';
            if (!endpoint.startsWith('/')) {
                throw new Error('Invalid API endpoint');
            }
            
            const baseUrl = new URL(window.FVARS.SERVER_API_URL);
            const url = new URL(endpoint, baseUrl);
            
            if (url.origin !== baseUrl.origin || url.hostname !== baseUrl.hostname) {
                throw new Error('Invalid API endpoint');
            }
            
            const response = await fetch(url.href, { redirect: 'manual' });
            
            if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
                throw new Error('Redirects are not allowed');
            }
            const roles = await response.json();
            const roleArray = Array.isArray(roles) ? roles : (roles.roles || []);
            const role = roleArray.find(r => r.Id == this._gRoleId);
            
            if (role) {
                this.setRole(role.Name);
            } else {
                // Fallback role mapping
                const roleMap = { 1: 'Member', 2: 'Editor', 4: 'Admin' };
                this.setRole(roleMap[this._gRoleId] || 'Member');
            }
            console.log('Role set to:', this._gRole, 'for RoleId:', this._gRoleId);
        } catch (error) {
            const errorMessage = error && error.message ? error.message : 'Unknown error';
            console.error('Error loading role name:', errorMessage);
            // Fallback role mapping
            const roleMap = { 1: 'Member', 2: 'Editor', 4: 'Admin' };
            this.setRole(roleMap[this._gRoleId] || 'Member');
        }
    }
}

// Manual role setting for testing
window.setTestRole = function(role, roleId) {
    GlobalAuth.setRole(role);
    GlobalAuth.setRoleId(roleId || 1);
    console.log('Test role set to:', role);
    RolePermissions.applyRoleBasedUI();
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    GlobalAuth.initialize();
});
const API_BASE_URL = window.FVARS.SECURE_API_URL;
let applications = [];
let currentUser = null;

function redirectToLogin(message) {
    if (message) {
        alert(message);
    }
    window.location.href = 'index.html';
}

function showAlert(message) {
    const alert = document.getElementById('alert');
    alert.textContent = message;
    alert.classList.add('show');
}

async function apiCall(endpoint, method = 'GET', data = null) {
    if (!endpoint || typeof endpoint !== 'string' || !endpoint.startsWith('/')) {
        throw new Error('Invalid API endpoint');
    }
    
    if (endpoint.includes('..') || endpoint.includes('//') || endpoint.includes('\\')) {
        throw new Error('Invalid API endpoint');
    }
    
    if (endpoint.includes('%') || endpoint.includes('@')) {
        throw new Error('Invalid API endpoint');
    }
    
    const token = localStorage.getItem('adminSessionId') || localStorage.getItem('userSessionId');
    
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'include',
        redirect: 'manual'
    };
    
    if (token) {
        options.headers['Authorization'] = `Bearer ${token}`;
    }

    if (data) {
        options.body = JSON.stringify(data);
    }

    try {
        const baseUrl = new URL(API_BASE_URL);
        
        // Construct URL safely using URL constructor
        const url = new URL(endpoint, API_BASE_URL);
        
        if (url.origin !== baseUrl.origin || url.hostname !== baseUrl.hostname) {
            throw new Error('Invalid API endpoint');
        }
        
        // Validate protocol is http or https only
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            throw new Error('Invalid protocol');
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
        
        const response = await fetch(url.href, options);
        
        if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
            throw new Error('Redirects are not allowed');
        }
        
        if (!response.ok) {
            if (response.status === 401) {
                redirectToLogin('Session expired. Please login again.');
                return null;
            } else if (response.status === 403) {
                redirectToLogin('Access denied.');
                return null;
            }
            
            let errorMessage = `HTTP error! status: ${response.status}`;
            try {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const errorData = await response.json();
                    errorMessage = errorData.message || errorMessage;
                } else {
                    const text = await response.text();
                    errorMessage = text || errorMessage;
                }
            } catch (e) {
                const errorMessage = e && e.message ? e.message : 'Unknown error';
                console.error('Error parsing response:', errorMessage);
            }
            throw new Error(errorMessage);
        }
        
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Server returned non-JSON response');
        }
        
        return await response.json();
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.error('API call failed:', errorMessage);
        
        if (error.message.includes('fetch')) {
            throw new Error('Cannot connect to server. Please check if the server is running.');
        }
        
        throw error;
    }
}

async function loadApplications() {
    try {
        const result = await apiCall('/api/user-applications');
        if (!result) return;
        applications = result.data || result || [];
        
        renderApplications();
        
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.error('Error loading applications:', errorMessage);
        showAlert('Failed to load applications: ' + error.message);
        const appGrid = document.getElementById('appGrid');
        appGrid.textContent = '';
        const noAppsDiv = document.createElement('div');
        noAppsDiv.className = 'no-apps';
        noAppsDiv.textContent = 'No applications available';
        appGrid.appendChild(noAppsDiv);
    }
}

function renderApplications() {
    const appGrid = document.getElementById('appGrid');
    
    if (applications.length === 0) {
        appGrid.textContent = '';
        const noAppsDiv = document.createElement('div');
        noAppsDiv.className = 'no-apps';
        noAppsDiv.textContent = 'No applications assigned to your account';
        appGrid.appendChild(noAppsDiv);
        return;
    }
    
    appGrid.textContent = '';
    applications.forEach(app => {
        const appItem = document.createElement('div');
        appItem.className = 'app-item';
        appItem.onclick = () => launchApplication(app.application_id);
        
        const nameSpan = document.createElement('span');
        nameSpan.textContent = app.application_name;
        
        const infoSpan = document.createElement('span');
        infoSpan.className = 'info-icon';
        infoSpan.textContent = 'i';
        infoSpan.title = 'Application Info';
        infoSpan.onclick = (event) => {
            event.stopPropagation();
            // Validate application_id is a number
            const appId = parseInt(app.application_id);
            if (!isNaN(appId)) {
                window.showAppInfo(appId);
            }
        };
        
        appItem.appendChild(nameSpan);
        appItem.appendChild(infoSpan);
        appGrid.appendChild(appItem);
    });
}

async function launchApplication(appId) {
    try {
        const app = applications.find(a => a.application_id === appId);
        if (!app) {
            await acm_SecurePopUp('Application not found', 'OK:ok');
            return;
        }
        
        console.log('Launching app:', app);
        console.log('redirect_URL:', app.redirect_URL);
        
        if (!app.redirect_URL) {
            await acm_SecurePopUp('Application URL not configured. Please contact administrator.', 'OK:ok');
            return;
        }
        
        // Validate URL before opening
        try {
            const urlObj = new URL(app.redirect_URL);
            if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
                await acm_SecurePopUp('Invalid URL protocol. Only HTTP and HTTPS are allowed.', 'OK:ok');
                return;
            }
            
            // Validate against trusted domains
            const trustedDomains = [
                'localhost',
                '127.0.0.1',
                'secureaccess247.com',
                'iodd.com',
                'google.com',
                'microsoft.com'
            ];
            const isTrusted = trustedDomains.some(domain => 
                urlObj.hostname === domain || 
                urlObj.hostname.endsWith('.' + domain) ||
                urlObj.hostname.match(/^192\.168\./) ||
                urlObj.hostname.match(/^10\./) ||
                urlObj.hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)  
            );
            
            if (!isTrusted) {
                await acm_SecurePopUp('Application URL domain is not in the trusted list. Please contact administrator.', 'OK:ok');
                return;
            }
        } catch (e) {
            const errorMessage = e && e.message ? e.message : 'Unknown error';
            console.error('Invalid URL format:', errorMessage);
            await acm_SecurePopUp('Invalid URL format.', 'OK:ok');
            return;
        }
        
        const sanitizedAppName = String(app.application_name || '').replace(/[^a-zA-Z0-9\s-_]/g, '');
        const sanitizedAppId = parseInt(app.application_id) || 0;
        console.log('User launching application:', sanitizedAppName, 'ID:', sanitizedAppId);
        window.open(app.redirect_URL, '_blank', 'noopener,noreferrer');
        
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.error('Error launching application:', errorMessage);
        await acm_SecurePopUp('Failed to launch application: ' + errorMessage, 'OK:ok');
    }
}

window.showAppInfo = async function(appId) {
    const app = applications.find(a => a.application_id === appId);
    if (!app) return;
    
    const appName = String(app.application_name || '').replace(/[<>"'&]/g, '');
    const appDesc = String(app.description || 'No description available').replace(/[<>"'&]/g, '');
    await acm_SecurePopUp(`Application: ${appName}\n\nDescription: ${appDesc}`, 'OK:ok');
}

function returnToLogin() {
    localStorage.removeItem('adminSessionId');
    localStorage.removeItem('userSessionId');
    window.location.href = 'index.html';
}

function goToAdminPage() {
    window.location.href = 'admin-page.html';
}

function goToProfilePage() {
    window.location.href = 'profile-page.html';
}

async function checkUserRole() {
    try {
        const result = await apiCall('/api/auth/verify');
        if (!result || !result.data) {
            redirectToLogin('Authentication required');
            return;
        }
        
        currentUser = result.data;
        const roleButton = document.getElementById('roleButton');
        
        if (currentUser.role === 'Admin') {
            roleButton.textContent = 'Admin Page';
            roleButton.onclick = goToAdminPage;
            roleButton.style.display = 'block';
        } else {
            roleButton.textContent = 'Profile';
            roleButton.onclick = goToProfilePage;
            roleButton.style.display = 'block';
        }
        
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.error('Error checking user role:', errorMessage);
    }
}

window.addEventListener('load', async () => {
    await checkUserRole();
    await loadApplications();
});

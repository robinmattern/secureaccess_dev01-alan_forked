let API_BASE_URL = window.FVARS?.SECURE_API_URL || window.location.origin + '/api';
let authToken = null;
let currentUser = null;

/**
 * Get URL parameters from the query string
 * @returns {Object} Object containing URL parameters
 */
function getUrlParams() {
    const params = new URLSearchParams(window.location.search);
    return {
        auth_token: params.get('auth_token'),
        user_id: params.get('user_id'),
        username: params.get('username'),
        email: params.get('email'),
        role: params.get('role')
    };
}

/**
 * Toggle password visibility
 * @param {string} inputId - The ID of the password input field
 */
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const toggle = input.nextElementSibling;

    if (input.type === 'password') {
        input.type = 'text';
        toggle.textContent = '🙈';
    } else {
        input.type = 'password';
        toggle.textContent = '👁️';
    }
}

/**
 * Show alert message
 * @param {string} message - The message to display
 * @param {string} type - The alert type ('success' or 'error')
 */
function showAlert(message, type = 'error') {
    const alert = document.getElementById('alert');
    alert.textContent = message;
    alert.className = `alert ${type} show`;

    if (type === 'success') {
        setTimeout(hideAlert, 5000);
    }
}

/**
 * Hide alert message
 */
function hideAlert() {
    document.getElementById('alert').classList.remove('show');
}

/**
 * Show loading spinner
 */
function showLoading() {
    document.getElementById('loading').classList.add('show');
    document.querySelectorAll('.btn').forEach(btn => btn.disabled = true);
}

/**
 * Hide loading spinner
 */
function hideLoading() {
    document.getElementById('loading').classList.remove('show');
    document.querySelectorAll('.btn').forEach(btn => btn.disabled = false);
}

/**
 * Make API call with session authentication
 * @param {string} endpoint - The API endpoint
 * @param {string} method - HTTP method (GET, POST, PUT, DELETE)
 * @param {Object} data - Request body data
 * @returns {Promise<Object>} API response
 */
async function apiCall(endpoint, method = 'GET', data = null) {
    const adminSessionId = localStorage.getItem('adminSessionId');
    const userSessionId = localStorage.getItem('userSessionId');
    const sessionId = adminSessionId || userSessionId;
    
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'include'
    };
    
    if (sessionId) {
        options.headers['Authorization'] = `Bearer ${sessionId}`;
    }
    
    if (method !== 'GET' && window.csrfToken) {
        options.headers['X-CSRF-Token'] = window.csrfToken;
    }

    if (data) {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);

        if (!response.ok) {
            const errorText = await response.text();

            if (response.status === 401) {
                throw new Error('Session expired. Please login again.');
            } else if (response.status === 403) {
                throw new Error('Access denied.');
            }
            
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            throw new Error('Cannot connect to server.');
        }
        throw error;
    }
}

/**
 * Update user profile
 * @param {FormData} formData - Form data containing profile information
 */
async function updateProfile(formData) {
    try {
        showLoading();
        
        const updateData = {
            first_name: formData.get('firstName'),
            last_name: formData.get('lastName'),
            username: formData.get('username'),
            email: formData.get('email'),
            security_question_1: formData.get('securityQuestion1')
        };
        
        const securityAnswer1 = formData.get('securityAnswer1');
        if (securityAnswer1 && securityAnswer1.trim()) {
            updateData.security_answer_1 = securityAnswer1;
        }
        
        updateData.security_question_2 = formData.get('securityQuestion2');
        
        const securityAnswer2 = formData.get('securityAnswer2');
        if (securityAnswer2 && securityAnswer2.trim()) {
            updateData.security_answer_2 = securityAnswer2;
        }

        const password = formData.get('password');
        if (password && password.trim()) {
            updateData.password = password;
        }

        const result = await apiCall('/users/me', 'PUT', updateData);
        
        if (result.success) {
            showAlert('Profile updated successfully!', 'success');
            document.getElementById('password').value = '';
            document.getElementById('confirmPassword').value = '';
        }
    } catch (error) {
        showAlert(error.message, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Navigate back to application launcher
 */
function goBack() {
    window.location.href = 'app-launch.html';
}

/**
 * Initialize the profile page
 */
async function initializePage() {
    try {
        try {
            const csrfResponse = await fetch(`${API_BASE_URL.replace('/api', '')}/csrf-token`, { credentials: 'include' });
            if (csrfResponse.ok) {
                const csrfData = await csrfResponse.json();
                window.csrfToken = csrfData.csrfToken;
            }
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
        }
        
        const adminSessionId = localStorage.getItem('adminSessionId');
        const userSessionId = localStorage.getItem('userSessionId');
        
        try {
            if (window.FVARS?.SECURE_API_URL) {
                API_BASE_URL = window.FVARS.SECURE_API_URL;
            }
        } catch (error) {
            console.warn('Could not get server config, using default');
        }
        
        const result = await apiCall('/users/me', 'GET');
        
        if (result.success) {
            const user = result.data;
            currentUser = {
                user_id: user.user_id,
                username: user.username,
                email: user.email,
                role: user.role
            };
            
            document.getElementById('firstName').value = user.first_name || '';
            document.getElementById('lastName').value = user.last_name || '';
            document.getElementById('username').value = user.username || '';
            document.getElementById('email').value = user.email || '';
            document.getElementById('securityQuestion1').value = user.security_question_1 || '';
            document.getElementById('securityQuestion2').value = user.security_question_2 || '';
        } else {
            throw new Error('Failed to load profile');
        }
    } catch (error) {
        localStorage.removeItem('userSessionId');
        localStorage.removeItem('adminSessionId');
        
        showAlert('Session invalid. Please login again.', 'error');
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 2000);
    }
}

document.getElementById('profileForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const formData = new FormData(e.target);
    const password = formData.get('password');
    const confirmPassword = formData.get('confirmPassword');

    if (password && password !== confirmPassword) {
        showAlert('Passwords do not match', 'error');
        return;
    }

    await updateProfile(formData);
});

document.addEventListener('DOMContentLoaded', initializePage);

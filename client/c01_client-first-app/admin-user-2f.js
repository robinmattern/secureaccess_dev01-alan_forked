const API_BASE_URL = window.FVARS.SECURE_API_URL;
let currentUser = null;

async function checkAdminSession() {
    // Fetch CSRF token
    try {
        const response = await fetch(`${API_BASE_URL.replace('/api', '')}/csrf-token`, { credentials: 'include' });
        if (response.ok) {
            const data = await response.json();
            window.csrfToken = data.csrfToken;
        }
    } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
    }
    
    const sessionId = localStorage.getItem('adminSessionId');
    if (!sessionId) {
        alert('Access denied. Admin role required.');
        window.location.href = 'index.html';
        return false;
    }
    return true;
}

async function loadUserData() {
    const userId = localStorage.getItem('twoFactorUserId');
    if (!userId) {
        await acm_SecurePopUp('No user selected', 'OK:ok');
        window.location.href = 'admin-users.html';
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/users/${userId}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('adminSessionId')}`,
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'include'
        });
        
        if (response.status === 401 || response.status === 403) {
            await acm_SecurePopUp('Session expired or access denied. Please login again.', 'OK:ok');
            window.location.href = 'index.html';
            return;
        }
        
        if (!response.ok) throw new Error('Failed to load user');
        
        const result = await response.json();
        currentUser = result.data || result;
        
        document.getElementById('userName').textContent = `${currentUser.first_name} ${currentUser.last_name}`;
        document.getElementById('twoFactorEnabled').value = currentUser.two_factor_enabled || 'No';
        document.getElementById('twoFactorEmail').value = currentUser.two_factor_email || '';
        document.getElementById('twoFactorVerified').value = currentUser.two_factor_verified ? 'Yes' : 'No';
        
    } catch (error) {
        await acm_SecurePopUp('Error loading user: ' + error.message, 'OK:ok');
        window.location.href = 'admin-users.html';
    }
}

async function saveChanges() {
    try {
        const data = {
            two_factor_enabled: document.getElementById('twoFactorEnabled').value,
            two_factor_email: document.getElementById('twoFactorEmail').value,
            two_factor_verified: document.getElementById('twoFactorVerified').value === 'Yes' ? 1 : 0
        };
        
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('adminSessionId')}`,
            'X-Requested-With': 'XMLHttpRequest'
        };
        
        if (window.csrfToken) {
            headers['X-CSRF-Token'] = window.csrfToken;
        }
        
        const response = await fetch(`${API_BASE_URL}/users/${currentUser.user_id}`, {
            method: 'PUT',
            headers: headers,
            credentials: 'include',
            body: JSON.stringify(data)
        });
        
        if (response.status === 401 || response.status === 403) {
            await acm_SecurePopUp('Session expired or access denied. Please login again.', 'OK:ok');
            window.location.href = 'index.html';
            return;
        }
        
        if (!response.ok) throw new Error('Failed to save changes');
        
        await acm_SecurePopUp('Changes saved successfully', 'OK:ok');
        
    } catch (error) {
        await acm_SecurePopUp('Error saving changes: ' + error.message, 'OK:ok');
    }
}

function cancelChanges() {
    loadUserData();
}

async function testSMTP() {
    try {
        const email = document.getElementById('twoFactorEmail').value.trim();
        
        if (!email) {
            await acm_SecurePopUp('Please enter an email address', 'OK:ok');
            return;
        }
        
        const response = await fetch(`${API_BASE_URL}/test-2fa`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminSessionId')}`,
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ email })
        });
        
        if (response.status === 401 || response.status === 403) {
            await acm_SecurePopUp('Session expired or access denied. Please login again.', 'OK:ok');
            window.location.href = 'index.html';
            return;
        }
        
        const data = await response.json();
        
        if (!response.ok) {
            await acm_SecurePopUp('Test failed: ' + (data.message || 'Unknown error'), 'OK:ok');
        } else {
            await acm_SecurePopUp('Test message sent successfully to ' + email, 'OK:ok');
        }
    } catch (error) {
        await acm_SecurePopUp('Test failed: ' + error.message, 'OK:ok');
    }
}

async function generateBackupCodes() {
    try {
        const result = await acm_SecurePopUp('Generate 10 new backup codes? This will replace any existing codes.', 'Yes:yes', 'No:no');
        
        if (result !== 'yes') return;
        
        const response = await fetch(`${API_BASE_URL}/users/${currentUser.user_id}/backup-codes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminSessionId')}`,
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (response.status === 401 || response.status === 403) {
            await acm_SecurePopUp('Session expired or access denied. Please login again.', 'OK:ok');
            window.location.href = 'index.html';
            return;
        }
        
        const data = await response.json();
        
        if (!response.ok) {
            await acm_SecurePopUp('Failed to generate codes: ' + (data.message || 'Unknown error'), 'OK:ok');
        } else {
            const codesList = data.codes.join('\n');
            await acm_SecurePopUp(`Backup codes generated successfully. Save these codes securely:\n\n${codesList}\n\nThese codes can only be used once and will not be shown again.`, 'OK:ok');
        }
    } catch (error) {
        await acm_SecurePopUp('Error generating backup codes: ' + error.message, 'OK:ok');
    }
}

function returnToUsers() {
    window.location.href = 'admin-users.html';
}

window.addEventListener('load', () => {
    if (!checkAdminSession()) return;
    loadUserData();
});

const API_BASE_URL = window.FVARS.SECURE_API_URL;
const textarea = document.getElementById('smtpConfig');
const statusDiv = document.getElementById('status');

// Fetch CSRF token on page load
(async () => {
    try {
        const response = await fetch(`${API_BASE_URL.replace('/api', '')}/csrf-token`, { credentials: 'include' });
        if (response.ok) {
            const data = await response.json();
            window.csrfToken = data.csrfToken;
            console.log('CSRF token fetched');
        }
    } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
    }
})();

function checkAdminRole() {
    const sessionId = localStorage.getItem('adminSessionId');
    if (!sessionId) {
        alert('Access denied. Admin role required.');
        window.location.href = 'index.html';
        return false;
    }
    return true;
}

async function loadConfig() {
    try {
        const response = await fetch(`${API_BASE_URL}/smtp-config`, {
            headers: { 
                'Authorization': `Bearer ${localStorage.getItem('adminSessionId')}`,
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'include'
        });
        if (response.status === 401 || response.status === 403) {
            alert('Session expired or access denied. Please login again.');
            window.location.href = 'index.html';
            return;
        }
        if (!response.ok) throw new Error('Failed to load config');
        const data = await response.json();
        textarea.value = data.content;
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        showStatus('Error loading configuration: ' + errorMessage, 'error');
    }
}

async function saveConfig() {
    try {
        const response = await fetch(`${API_BASE_URL}/smtp-config`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminSessionId')}`,
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': window.csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ content: textarea.value })
        });
        if (response.status === 401 || response.status === 403) {
            alert('Session expired or access denied. Please login again.');
            window.location.href = 'index.html';
            return;
        }
        if (!response.ok) throw new Error('Failed to save config');
        showStatus('Configuration saved successfully', 'success');
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        showStatus('Error saving configuration: ' + errorMessage, 'error');
    }
}

function cancelConfig() {
    loadConfig();
    showStatus('Changes cancelled, configuration reloaded', 'success');
}

async function testConnection() {
    const testEmail = document.getElementById('testEmail').value.trim();
    console.log('Test button clicked, email:', testEmail);
    if (!testEmail) {
        await acm_SecurePopUp('Please enter an email address for testing', 'OK:ok');
        return;
    }
    try {
        console.log('Sending test request...');
        const response = await fetch(`${API_BASE_URL}/smtp-test`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminSessionId')}`,
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ content: textarea.value, testEmail })
        });
        console.log('Response status:', response.status);
        if (response.status === 401 || response.status === 403) {
            await acm_SecurePopUp('Session expired or access denied. Please login again.', 'OK:ok');
            window.location.href = 'index.html';
            return;
        }
        const data = await response.json();
        console.log('Response data:', data);
        if (!response.ok) {
            console.log('Test failed');
            await acm_SecurePopUp('Connection test failed: ' + (data.message || 'Unknown error'), 'OK:ok');
        } else {
            console.log('Test succeeded');
            await acm_SecurePopUp('The test email was sent to ' + testEmail, 'OK:ok');
        }
    } catch (error) {
        const errorMessage = error && error.message ? error.message : 'Unknown error';
        console.error('Test error:', errorMessage);
        await acm_SecurePopUp('Connection test failed: ' + errorMessage, 'OK:ok');
    }
}

function returnToAdmin() {
    window.location.href = 'admin-page.html';
}

function showStatus(message, type) {
    statusDiv.textContent = message;
    statusDiv.className = `status ${type}`;
    setTimeout(() => { statusDiv.className = 'status'; }, 5000);
}

window.addEventListener('load', () => {
    console.log('Page loaded, checking admin role...');
    console.log('acm_SecurePopUp defined:', typeof acm_SecurePopUp);
    if (checkAdminRole()) loadConfig();
    
    const testBtn = document.getElementById('testBtn');
    if (testBtn) {
        console.log('Test button found, adding listener');
        testBtn.addEventListener('click', testConnection);
    }
});

const API_BASE = 'http://localhost:57353/api';

// Register new user
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const userId = document.getElementById('userId').value;
    const allowedOrigins = document.getElementById('allowedOrigins').value
        .split('\n').filter(o => o.trim()).map(o => o.trim());
    const allowedApis = document.getElementById('allowedApis').value
        .split('\n').filter(a => a.trim()).map(a => a.trim());
    
    try {
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId, allowedOrigins, allowedApis })
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert(`User registered! API Key: ${result.apiKey}`);
            document.getElementById('registerForm').reset();
            loadUsers();
        } else {
            alert('Registration failed');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
});

// Load and display users
async function loadUsers() {
    try {
        const response = await fetch(`${API_BASE}/users`);
        const users = await response.json();
        
        const usersList = document.getElementById('usersList');
        usersList.innerHTML = '';
        
        Object.entries(users).forEach(([userId, user]) => {
            const userDiv = document.createElement('div');
            userDiv.className = 'user-item';
            userDiv.innerHTML = `
                <h3>${userId}</h3>
                <p><strong>API Key:</strong> <span class="api-key">${user.apiKey}</span></p>
                <p><strong>Origins:</strong> ${user.allowedOrigins.join(', ') || 'None'}</p>
                <p><strong>APIs:</strong> ${user.allowedApis.join(', ') || 'None'}</p>
                <p><strong>Status:</strong> ${user.active ? 'Active' : 'Inactive'}</p>
                <button onclick="deleteUser('${userId}')" style="background: #dc3545;">Delete</button>
            `;
            usersList.appendChild(userDiv);
        });
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

// Delete user
async function deleteUser(userId) {
    if (!confirm(`Delete user ${userId}?`)) return;
    
    try {
        await fetch(`${API_BASE}/users/${userId}`, { method: 'DELETE' });
        loadUsers();
    } catch (error) {
        alert('Error deleting user: ' + error.message);
    }
}

// Load users on page load
loadUsers();
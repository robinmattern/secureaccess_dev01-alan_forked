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
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const users = await response.json();
        
        const usersList = document.getElementById('usersList');
        usersList.innerHTML = '';
        
        Object.entries(users).forEach(([userId, user]) => {
            try {
                const userDiv = document.createElement('div');
                userDiv.className = 'user-item';
                
                const h3 = document.createElement('h3');
                h3.textContent = userId;
                
                const keyP = document.createElement('p');
                const keyStrong = document.createElement('strong');
                keyStrong.textContent = 'API Key: ';
                const keySpan = document.createElement('span');
                keySpan.className = 'api-key';
                keySpan.textContent = user.apiKey;
                keyP.appendChild(keyStrong);
                keyP.appendChild(keySpan);
                
                const originsP = document.createElement('p');
                const originsStrong = document.createElement('strong');
                originsStrong.textContent = 'Origins: ';
                originsP.appendChild(originsStrong);
                originsP.appendChild(document.createTextNode(user.allowedOrigins.join(', ') || 'None'));
                
                const apisP = document.createElement('p');
                const apisStrong = document.createElement('strong');
                apisStrong.textContent = 'APIs: ';
                apisP.appendChild(apisStrong);
                apisP.appendChild(document.createTextNode(user.allowedApis.join(', ') || 'None'));
                
                const statusP = document.createElement('p');
                const statusStrong = document.createElement('strong');
                statusStrong.textContent = 'Status: ';
                statusP.appendChild(statusStrong);
                statusP.appendChild(document.createTextNode(user.active ? 'Active' : 'Inactive'));
                
                const deleteBtn = document.createElement('button');
                deleteBtn.textContent = 'Delete';
                deleteBtn.style.background = '#dc3545';
                deleteBtn.dataset.userId = userId;
                
                userDiv.appendChild(h3);
                userDiv.appendChild(keyP);
                userDiv.appendChild(originsP);
                userDiv.appendChild(apisP);
                userDiv.appendChild(statusP);
                userDiv.appendChild(deleteBtn);
                
                usersList.appendChild(userDiv);
            } catch (error) {
                console.error(`Error rendering user ${userId}:`, error.message || 'Unknown error');
            }
        });
    } catch (error) {
        console.error('Error loading users:', error.message || 'Unknown error');
        const usersList = document.getElementById('usersList');
        if (usersList) {
            usersList.innerHTML = '<p style="color: red;">Failed to load users</p>';
        }
    }
}

// Delete user
async function deleteUser(userId) {
    if (!confirm(`Delete user ${userId}?`)) return;
    
    try {
        const response = await fetch(`${API_BASE}/users/${userId}`, { method: 'DELETE' });
        if (!response.ok) {
            throw new Error(`Failed to delete user: ${response.status}`);
        }
        loadUsers();
    } catch (error) {
        console.error('Error deleting user:', error.message || 'Unknown error');
        alert('Error deleting user: ' + error.message);
    }
}

// Event delegation for delete buttons
document.getElementById('usersList').addEventListener('click', (e) => {
    if (e.target.tagName === 'BUTTON' && e.target.dataset.userId) {
        deleteUser(e.target.dataset.userId);
    }
});

// Load users on page load
loadUsers();
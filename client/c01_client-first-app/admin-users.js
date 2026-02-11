        // Authentication will be handled by server-side verification
        // No client-side token checks needed with HTTP-only cookies
        
        // Configuration   - will be set dynamically from server
        let API_BASE_URL   =  window.FVARS.SECURE_API_URL;
        let SECURE_API_URL =  window.FVARS.SECURE_API_URL; 
        
        // State management
        let users = [];
        let selectedUser = null;
        let isEditing = false;
        let isNewUser = false;

        // DOM elements
        const userGrid = document.getElementById('userGrid');
        const formContainer = document.getElementById('formContainer');
        const formLoading = document.getElementById('formLoading');
        const userForm = document.getElementById('userForm');
        const alert = document.getElementById('alert');
        const addUserBtn = document.getElementById('addUserBtn');
        const deleteBtn = document.getElementById('deleteBtn');
        const submitBtn = document.getElementById('submitBtn');
        const cancelBtn = document.getElementById('cancelBtn');
        const returnBtn = document.getElementById('returnBtn');
        const twoFactorBtn = document.getElementById('twoFactorBtn');

        // Helper functions
        async function redirectToLogin(message) {
            localStorage.removeItem('adminSessionId');
            const result = await acm_SecurePopUp(message, "OK:ok");
            window.location.href = 'index.html';
        }
        
        // Check if hostname is internal IP
        function isInternalIP(hostname) {
            return hostname === 'localhost' || 
                   hostname === '127.0.0.1' || 
                   hostname.startsWith('192.168.') || 
                   hostname.startsWith('10.') || 
                   hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
        }
        
        // Cache base URL
        let cachedBaseUrl = null;
        
        function initializeAdminPage() {
            // Hide loading screen and show the users page content
            document.getElementById('authLoading').style.display = 'none';
            document.body.style.display = 'block';
        }

        // Check admin session authentication
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
            
            const adminSessionId = localStorage.getItem('adminSessionId');
            const userSessionId = localStorage.getItem('userSessionId');
            const sessionId = adminSessionId || userSessionId;
            
            if (!sessionId) {
                console.error('❌ No session found in localStorage');
                redirectToLogin('No session found. Please login.');
                return;
            }
            
            // If user has userSessionId (not admin), redirect to profile page
            if (!adminSessionId && userSessionId) {
                window.location.href = 'profile-page.html';
                return;
            }
            
            initializeAdminPage();
            setTimeout(loadUsers, 100);
        }
        
        // Initialize with session check
        window.addEventListener('load', checkAdminSession);

        // API functions with session authentication
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
            
            const adminSessionId = localStorage.getItem('adminSessionId');
            const userSessionId = localStorage.getItem('userSessionId');
            const sessionId = adminSessionId || userSessionId;
            
            const options = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionId}`,
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'include',
                redirect: 'manual'
            };
            
            if (method !== 'GET' && window.csrfToken) {
                options.headers['X-CSRF-Token'] = window.csrfToken;
            }

            if (data) {
                options.body = JSON.stringify(data);
            }

            try {
                // Use cached base URL or create new one
                if (!cachedBaseUrl) {
                    cachedBaseUrl = new URL(API_BASE_URL);
                }
                
                // Construct URL safely using URL constructor
                const url = new URL(endpoint, API_BASE_URL);
                
                if (url.origin !== cachedBaseUrl.origin || url.hostname !== cachedBaseUrl.hostname) {
                    throw new Error('Invalid API endpoint');
                }
                
                // Validate protocol is http or https only
                if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                    throw new Error('Invalid protocol');
                }
                
                if (isInternalIP(url.hostname) && !isInternalIP(cachedBaseUrl.hostname)) {
                    throw new Error('Access to internal networks is not allowed');
                }
                
                const response = await fetch(url.href, options);
                
                if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
                    throw new Error('Redirects are not allowed');
                }
                
                if (!response.ok) {
                    // Handle specific authentication errors
                    if (response.status === 401) {
                        const errorData = await response.json().catch(() => ({}));
                        
                        if (errorData.code === 'TOKEN_EXPIRED') {
                            redirectToLogin('Your session has expired. Please login again.');
                        } else if (errorData.code === 'TOKEN_INVALID') {
                            redirectToLogin('Invalid authentication. Please login again.');
                        } else {
                            redirectToLogin('Authentication failed. Please login again.');
                        }
                        return;
                    } else if (response.status === 403) {
                        redirectToLogin('Access denied. Admin privileges required.');
                        return;
                    }
                    
                    let errorMessage = `HTTP error! status: ${response.status}`;
                    try {
                        const errorData = await response.json();
                        errorMessage = errorData.message || errorMessage;
                    } catch (e) {
                        const errorMessage = e && e.message ? e.message : 'Unknown error';
                        console.error('JSON parse error:', errorMessage);
                    }
                    throw new Error(errorMessage);
                }
                
                return await response.json();
            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('API call failed:', errorMessage);
                
                // Check if it's a network error (server down)
                if (error.message.includes('fetch')) {
                    throw new Error('Cannot connect to server. Please check if the server is running.');
                }
                
                throw error;
            }
        }

        // Show admin popup
        function showAdminPopup() {
            document.getElementById('adminPopup').classList.add('show');
        }

        // Hide admin popup
        function hideAdminPopup() {
            document.getElementById('adminPopup').classList.remove('show');
        }

        // Go to Landing Page
        function goToLandingPage() {
            hideAdminPopup();
            
            // Get current auth token and user info
            const token = authToken || localStorage.getItem('authToken');
            if (token && currentUser) {
                const params = new URLSearchParams({
                    auth_token: token,
                    user_id: currentUser.user_id || currentUser.userId,
                    username: currentUser.username,
                    email: currentUser.email,
                    role: currentUser.role,
                    login_status: 'success'
                });
                window.location.href = `${LandingPage}?${params.toString()}`;
            } else {
                window.location.href = LandingPage;
            }
        }

        // Go to User Page
        function goToAdminPage() {
            hideAdminPopup();
            window.location.href = 'admin-users.html';
        }
        // State for alert timeout
        let alertTimeout = null;
        
        function showAlert(message, type = 'error') {
            // Clear any existing timeout
            if (alertTimeout) {
                clearTimeout(alertTimeout);
                alertTimeout = null;
            }
            
            alert.textContent = message;
            alert.className = `alert ${type} show`;
            
            if (type === 'success') {
                alertTimeout = setTimeout(() => {
                    alert.classList.remove('show');
                    alertTimeout = null;
                }, 3000);
            }
        }

        function hideAlert() {
            if (alertTimeout) {
                clearTimeout(alertTimeout);
                alertTimeout = null;
            }
            alert.classList.remove('show');
        }

        // Show delete confirmation popup
        function showDeletePopup() {
            if (!selectedUser || !selectedUser.user_id) {
                showAlert('No user selected for deletion');
                return;
            }

            const userName = `${selectedUser.first_name || ''} ${selectedUser.last_name || ''}`.trim() || selectedUser.username;
            document.getElementById('deleteUserName').textContent = userName;
            document.getElementById('deletePopup').classList.add('show');
            
            // Focus on the cancel button (default action)
            setTimeout(() => {
                document.querySelector('.btn-delete-cancel').focus();
            }, 100);
        }

        // Hide delete confirmation popup
        function hideDeletePopup() {
            document.getElementById('deletePopup').classList.remove('show');
        }

        // Confirm delete action
        async function confirmDelete() {
            if (!selectedUser || !selectedUser.user_id) {
                hideDeletePopup();
                showAlert('No user selected for deletion');
                return;
            }

            try {
                hideDeletePopup();
                
                await apiCall(`/api/users/${selectedUser.user_id}`, 'DELETE');
                
                showAlert('User deleted successfully', 'success');
                
                // Reset form and reload users
                formContainer.style.display = 'none';
                selectedUser = null;
                deleteBtn.disabled = true;
                submitBtn.disabled = true;
                
                await loadUsers();

            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Error deleting user:', errorMessage);
                showAlert('Failed to delete user: ' + errorMessage);
            }
        }

        // Load all users
        async function loadUsers() {
            try {
                userGrid.innerHTML = '<div class="loading show"><div class="spinner"></div><p>Loading users...</p></div>';
                
                const result = await apiCall('/api/users');
                users = result.data || result || [];
                
                renderUserGrid();
                
            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Error loading users:', errorMessage);
                showAlert('Failed to load users: ' + errorMessage);
                userGrid.innerHTML = '<div style="padding: 20px; text-align: center; color: #dc3545;">Failed to load users</div>';
            }
        }

        // Render user grid
        function renderUserGrid() {
            if (users.length === 0) {
                userGrid.innerHTML = '<div style="padding: 20px; text-align: center; color: #6c757d;">No users found</div>';
                return;
            }

            userGrid.innerHTML = '';
            users.forEach(user => {
                const userItem = document.createElement('div');
                userItem.className = 'user-item';
                userItem.setAttribute('data-user-id', user.user_id);
                userItem.onclick = () => selectUser(user.user_id);
                
                const nameDiv = document.createElement('div');
                nameDiv.className = 'name';
                const fullName = `${user.first_name || ''} ${user.last_name || ''}`.trim();
                nameDiv.textContent = fullName || 'No Name';
                
                const detailsDiv = document.createElement('div');
                detailsDiv.className = 'details';
                const status = user.account_status || 'active';
                detailsDiv.textContent = `${user.username} • ${status}`;
                
                userItem.appendChild(nameDiv);
                userItem.appendChild(detailsDiv);
                userGrid.appendChild(userItem);
            });
        }

        // Select user
        async function selectUser(userId) {
            try {
                
                // Update grid selection
                document.querySelectorAll('.user-item').forEach(item => {
                    item.classList.remove('selected');
                });
                document.querySelector(`[data-user-id="${userId}"]`).classList.add('selected');

                // Show loading
                formLoading.style.display = 'block';
                formContainer.style.display = 'none';

                // Load user details
                const result = await apiCall(`/api/users/${userId}`);
                selectedUser = result.data || result;

                populateForm(selectedUser);
                
                // Show form and enable buttons
                formLoading.style.display = 'none';
                formContainer.style.display = 'block';
                deleteBtn.disabled = selectedUser.username === 'SAAdmin'; // Disable delete for SAAdmin
                submitBtn.disabled = false;
                isEditing = false;
                isNewUser = false;

                hideAlert();

            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Error loading user:', errorMessage);
                formLoading.style.display = 'none';
                showAlert('Failed to load user details: ' + error.message);
            }
        }

        // Apply SAAdmin restrictions
        function applySAAdminRestrictions(user) {
            const isSAAdmin = user && user.username === 'SAAdmin';
            
            if (isSAAdmin) {
                // Disable delete button for SAAdmin
                deleteBtn.disabled = true;
                
                // Disable fields that SAAdmin cannot edit
                document.getElementById('firstName').disabled = true;
                document.getElementById('lastName').disabled = true;
                document.getElementById('username').disabled = true;
                document.getElementById('email').disabled = true;
                document.getElementById('role').disabled = true;
                document.getElementById('twoFactorEnabled').disabled = true;
                
                // Enable only allowed fields for SAAdmin
                document.getElementById('accountStatus').disabled = false;
                document.getElementById('tokenExpiration').disabled = false;
                document.getElementById('password').disabled = false;
                document.getElementById('securityQuestion1').disabled = false;
                document.getElementById('securityAnswer1').disabled = false;
                document.getElementById('securityQuestion2').disabled = false;
                document.getElementById('securityAnswer2').disabled = false;
            } else {
                // Enable all fields for non-SAAdmin users
                document.getElementById('firstName').disabled = false;
                document.getElementById('lastName').disabled = false;
                document.getElementById('username').disabled = false;
                document.getElementById('email').disabled = false;
                document.getElementById('role').disabled = false;
                document.getElementById('accountStatus').disabled = false;
                document.getElementById('tokenExpiration').disabled = false;
                document.getElementById('password').disabled = false;
                document.getElementById('securityQuestion1').disabled = false;
                document.getElementById('securityAnswer1').disabled = false;
                document.getElementById('securityQuestion2').disabled = false;
                document.getElementById('securityAnswer2').disabled = false;
            }
        }

        // Populate form with user data
        function populateForm(user) {
            
            document.getElementById('userId').value = user.user_id || '';
            document.getElementById('firstName').value = user.first_name || '';
            document.getElementById('lastName').value = user.last_name || '';
            document.getElementById('username').value = user.username || '';
            document.getElementById('email').value = user.email || '';
            document.getElementById('accountStatus').value = user.account_status || 'active';
            document.getElementById('tokenExpiration').value = user.token_expiration_minutes || 60;
            document.getElementById('twoFactorEnabled').value = user.two_factor_enabled || 'No';
            document.getElementById('twoFactorBtn').disabled = false;
            document.getElementById('role').value = user.role || 'User';
            document.getElementById('securityQuestion1').value = user.security_question_1 || '';
            document.getElementById('securityQuestion2').value = user.security_question_2 || '';
            document.getElementById('createdAt').value = user.created_at ? new Date(user.created_at).toLocaleString() : '';
            document.getElementById('updatedAt').value = user.updated_at ? new Date(user.updated_at).toLocaleString() : '';
            document.getElementById('lastLogin').value = user.last_login_timestamp ? new Date(user.last_login_timestamp).toLocaleString() : '';
            
            // Clear password field
            document.getElementById('password').value = '';
            
            // Handle security answers - show placeholder if they exist, clear if they don't
            const answer1Field = document.getElementById('securityAnswer1');
            const answer2Field = document.getElementById('securityAnswer2');
            
            if (user.security_answer_1_hash && user.security_answer_1_hash.length > 0) {
                answer1Field.value = '';
                answer1Field.placeholder = 'Leave empty to keep current answer';
            } else {
                answer1Field.value = '';
                answer1Field.placeholder = 'Enter security answer';
            }
            
            if (user.security_answer_2_hash && user.security_answer_2_hash.length > 0) {
                answer2Field.value = '';
                answer2Field.placeholder = 'Leave empty to keep current answer';
            } else {
                answer2Field.value = '';
                answer2Field.placeholder = 'Enter security answer';
            }
            
            // Apply SAAdmin restrictions after populating form
            applySAAdminRestrictions(user);
        }

        // Add new user
        addUserBtn.addEventListener('click', () => {
            // Clear selection
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('selected');
            });

            // Clear form
            userForm.reset();
            document.getElementById('userId').value = '';
            document.getElementById('accountStatus').value = 'active';
            document.getElementById('tokenExpiration').value = 60;
            document.getElementById('role').value = 'User';
            document.getElementById('createdAt').value = '';
            document.getElementById('updatedAt').value = '';
            document.getElementById('lastLogin').value = '';

            // Show form
            formContainer.style.display = 'block';
            formLoading.style.display = 'none';

            // Update state and buttons
            selectedUser = null;
            isNewUser = true;
            isEditing = true;
            deleteBtn.disabled = true;
            submitBtn.disabled = false;

            hideAlert();
            document.getElementById('firstName').focus();
        });

        // Delete user - UPDATED TO USE acm_SecurePopUp
        deleteBtn.addEventListener('click', async () => {
            if (!selectedUser || !selectedUser.user_id) {
                showAlert('No user selected for deletion');
                return;
            }

            const userName = `${selectedUser.first_name || ''} ${selectedUser.last_name || ''}`.trim() || selectedUser.username;
            const delete_respond = await acm_SecurePopUp(`Do you want to delete user: ${userName}?`, "Yes:yes", "No:no");
            
            if (delete_respond === 'yes') {
                try {
                    await apiCall(`/api/users/${selectedUser.user_id}`, 'DELETE');
                    
                    showAlert('User deleted successfully', 'success');
                    
                    // Reset form and reload users
                    formContainer.style.display = 'none';
                    selectedUser = null;
                    deleteBtn.disabled = true;
                    submitBtn.disabled = true;
                    
                    await loadUsers();

                } catch (error) {
                    const errorMessage = error && error.message ? error.message : 'Unknown error';
                    console.error('Error deleting user:', errorMessage);
                    showAlert('Failed to delete user: ' + errorMessage);
                }
            }
        });

        // Handle escape key to close popup
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && document.getElementById('deletePopup').classList.contains('show')) {
                hideDeletePopup();
            }
        });

        // Submit changes - FIXED VERSION
        submitBtn.addEventListener('click', async () => {
            try {
                // Validate required fields first
                const firstName = document.getElementById('firstName').value.trim();
                const lastName = document.getElementById('lastName').value.trim();
                const username = document.getElementById('username').value.trim();
                const email = document.getElementById('email').value.trim();

                if (!firstName || !lastName || !username || !email) {
                    showAlert('Please fill in all required fields (First Name, Last Name, Username, Email)');
                    return;
                }

                // Build the update data object manually
                const userData = {
                    first_name: firstName,
                    last_name: lastName,
                    username: username,
                    email: email,
                    account_status: document.getElementById('accountStatus').value,
                    token_expiration_minutes: parseInt(document.getElementById('tokenExpiration').value) || 60,
                    two_factor_enabled: document.getElementById('twoFactorEnabled').value,
                    role: document.getElementById('role').value
                };

                // Add password only if it's provided
                const password = document.getElementById('password').value.trim();
                if (password) {
                    userData.password = password;
                }
                
                // Validate password for new users
                if (isNewUser && !password) {
                    showAlert('Password is required for new users');
                    return;
                }

                // Add security questions if provided
                const securityQuestion1 = document.getElementById('securityQuestion1').value.trim();
                const securityAnswer1 = document.getElementById('securityAnswer1').value.trim();
                const securityQuestion2 = document.getElementById('securityQuestion2').value.trim();
                const securityAnswer2 = document.getElementById('securityAnswer2').value.trim();

                // Always include security questions if they have values
                if (securityQuestion1) {
                    userData.security_question_1 = securityQuestion1;
                }
                if (securityAnswer1) {
                    userData.security_answer_1 = securityAnswer1;
                }
                if (securityQuestion2) {
                    userData.security_question_2 = securityQuestion2;
                }
                if (securityAnswer2) {
                    userData.security_answer_2 = securityAnswer2;
                }

                const REDACTED_PLACEHOLDER = '***HIDDEN***';
                const sanitizedData = { ...userData };
                if (sanitizedData.password) sanitizedData.password = REDACTED_PLACEHOLDER;
                if (sanitizedData.security_answer_1) sanitizedData.security_answer_1 = REDACTED_PLACEHOLDER;
                if (sanitizedData.security_answer_2) sanitizedData.security_answer_2 = REDACTED_PLACEHOLDER;
                console.log('Submitting user data:', sanitizedData);

                let result;
                if (isNewUser) {
                    if (!password) {
                        showAlert('Password is required for new users');
                        return;
                    }
                    result = await apiCall('/api/users', 'POST', userData);
                    showAlert('User created successfully', 'success');
                } else {
                    result = await apiCall(`/api/users/${selectedUser.user_id}`, 'PUT', userData);
                    showAlert('User updated successfully', 'success');
                }

                console.log('API Response:', result);

                // Reload users list to show changes
                await loadUsers();
                
                if (isNewUser) {
                    // Try to select the newly created user if possible
                    const newUserId = result.data?.user_id || result.user_id;
                    if (newUserId) {
                        await selectUser(newUserId);
                    } else {
                        // Clear form if we can't select the new user
                        formContainer.style.display = 'none';
                        selectedUser = null;
                        deleteBtn.disabled = true;
                        submitBtn.disabled = true;
                    }
                } else {
                    // For updates, refresh the selected user data
                    if (selectedUser && selectedUser.user_id) {
                        await selectUser(selectedUser.user_id);
                    }
                }

                isEditing = false;
                isNewUser = false;

            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Error saving user:', errorMessage);
                showAlert('Failed to save user: ' + errorMessage);
            }
        });

        // Cancel changes
        cancelBtn.addEventListener('click', async () => {
            if (isEditing && (isNewUser || selectedUser)) {
                const result = await acm_SecurePopUp('Are you sure you want to cancel? All unsaved changes will be lost.', 'Yes:yes', 'No:no');
                if (result !== 'yes') {
                    return;
                }
            }

            // Reset everything
            if (selectedUser && !isNewUser) {
                populateForm(selectedUser);
            } else {
                formContainer.style.display = 'none';
                document.querySelectorAll('.user-item').forEach(item => {
                    item.classList.remove('selected');
                });
                selectedUser = null;
                deleteBtn.disabled = true;
                submitBtn.disabled = true;
            }

            isEditing = false;
            isNewUser = false;
            hideAlert();
        });

        // Return to admin page
        returnBtn.addEventListener('click', () => {
            window.location.href = 'admin-page.html';
        });
        
        // 2-Factor Authentication button
        twoFactorBtn.addEventListener('click', () => {
            if (selectedUser && selectedUser.user_id) {
                localStorage.setItem('twoFactorUserId', selectedUser.user_id);
                window.location.href = 'admin-user-2f.html';
            }
        });

        // Enable form change tracking
        userForm.addEventListener('input', () => {
            isEditing = true;
        });

        // Initialize the application
        document.addEventListener('DOMContentLoaded', async () => {
            console.log('Users Page initialized');
            
            // Get dynamic configuration
            try {
                const config = await ConfigManager.getConfig();
                API_BASE_URL = config.apiBaseUrl;
                console.log('Using API URL:', API_BASE_URL);
            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.warn('Could not get server config, using default:', errorMessage);
            }
            
            // Check if server is running
            fetch(`${API_BASE_URL.replace('/api', '')}/health`)
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'OK') {
                        console.log('✅ Server connection successful');
                    }
                })
                .catch(error => {
                    console.warn('⚠️ Server not reachable. Make sure your API server is running.');
                    showAlert('Server not reachable. Please ensure the API server is running.');
                });
        });

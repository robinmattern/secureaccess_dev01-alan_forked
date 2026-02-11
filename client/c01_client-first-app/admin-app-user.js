        // acm_Prompts.js inline
        const ACM_APP_TITLE = 'SecureAccess';
        
        function acm_SecurePopUp(message, ...buttonDefinitions) {
            return new Promise((resolve, reject) => {
                const WindowCaption = ACM_APP_TITLE;
                if (typeof message !== 'string' || message.trim() === '') {
                    reject(new Error('Message must be a non-empty string'));
                    return;
                }
                if (buttonDefinitions.length === 0) {
                    reject(new Error('At least one button must be defined'));
                    return;
                }
                if (buttonDefinitions.length > 10) {
                    reject(new Error('Maximum 10 buttons allowed'));
                    return;
                }
                const buttons = [];
                for (let i = 0; i < buttonDefinitions.length; i++) {
                    const buttonDef = buttonDefinitions[i];
                    if (typeof buttonDef !== 'string') {
                        reject(new Error(`Button definition ${i + 1} must be a string`));
                        return;
                    }
                    const parts = buttonDef.split(':');
                    if (parts.length !== 2) {
                        reject(new Error(`Invalid button format at position ${i + 1}. Use "Label : Value"`));
                        return;
                    }
                    const label = parts[0].trim();
                    const value = parts[1].trim();
                    if (label === '' || value === '') {
                        reject(new Error(`Button label and value cannot be empty at position ${i + 1}`));
                        return;
                    }
                    if (!/^[\w\s\-.,!?()]+$/.test(label)) {
                        reject(new Error(`Button label contains invalid characters at position ${i + 1}`));
                        return;
                    }
                    buttons.push({ label, value });
                }
                const overlay = document.createElement('div');
                const modal = document.createElement('div');
                const titleDiv = document.createElement('div');
                const messageDiv = document.createElement('div');
                const buttonsContainer = document.createElement('div');
                overlay.style.cssText = `position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.5); z-index: 999999; display: flex; align-items: center; justify-content: center; font-family: Arial, sans-serif;`;
                modal.style.cssText = `background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3); max-width: 500px; min-width: 300px; padding: 0; margin: 20px; max-height: 80vh; overflow: hidden;`;
                titleDiv.style.cssText = `padding: 20px 24px 12px 24px; font-size: 18px; font-weight: bold; color: #333; border-bottom: 1px solid #eee; background: #e3f2fd;`;
                titleDiv.textContent = WindowCaption;
                messageDiv.style.cssText = `padding: 16px 24px; font-size: 16px; line-height: 1.5; color: #333; word-wrap: break-word;`;
                if (message.length > 1000) message = message.substring(0, 1000);
                messageDiv.textContent = message;
                buttonsContainer.style.cssText = `padding: 16px 24px 24px 24px; display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end;`;
                buttons.forEach((button, index) => {
                    const btn = document.createElement('button');
                    btn.textContent = button.label;
                    btn.setAttribute('data-value', button.value);
                    btn.setAttribute('type', 'button');
                    btn.style.cssText = `background: ${index === 0 ? '#007bff' : '#6c757d'}; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 14px; min-width: 70px;`;
                    btn.addEventListener('click', (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        const selectedValue = btn.getAttribute('data-value');
                        cleanup();
                        resolve(selectedValue);
                    });
                    buttonsContainer.appendChild(btn);
                });
                function cleanup() {
                    if (overlay && overlay.parentNode) {
                        overlay.parentNode.removeChild(overlay);
                    }
                }
                modal.appendChild(titleDiv);
                modal.appendChild(messageDiv);
                modal.appendChild(buttonsContainer);
                overlay.appendChild(modal);
                document.body.appendChild(overlay);
            });
        }
        let API_BASE_URL = window.FVARS.SECURE_API_URL;
        
        // State management
        let applications = [];
        let users = [];
        let appUsers = [];
        let selectedApplication = null;
        let selectedAppUser = null;
        let currentAppUserId = 0; // 0 = new record, >0 = existing record

        // DOM elements
        const appGrid = document.getElementById('appGrid');
        const formContainer = document.getElementById('formContainer');
        const formLoading = document.getElementById('formLoading');
        const alertElement = document.getElementById('alert');
        const appDescription = document.getElementById('appDescription');
        const userGrid = document.getElementById('userGrid');
        const userSelect = document.getElementById('userSelect');
        const appRoleSelect = document.getElementById('appRoleSelect');
        const statusSelect = document.getElementById('statusSelect');
        const trackUserSelect = document.getElementById('trackUserSelect');
        const startDate = document.getElementById('startDate');
        const endDate = document.getElementById('endDate');
        const assignBtn = document.getElementById('assignBtn');
        const removeBtn = document.getElementById('removeBtn');
        const updateBtn = document.getElementById('updateBtn');
        const cancelBtn = document.getElementById('cancelBtn');
        const returnBtn = document.getElementById('returnBtn');

        // Helper functions
        async function redirectToLogin(message) {
            localStorage.removeItem('adminSessionId');
            const result = await acm_SecurePopUp(message, "OK:ok");
            window.location.href = 'index.html';
        }

        // API functions with session authentication
        async function apiCall(endpoint, method = 'GET', data = null) {
            const sessionId = localStorage.getItem('adminSessionId');
            
            const options = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${sessionId}`,
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'include'
            };
            
            if (method !== 'GET' && window.csrfToken) {
                options.headers['X-CSRF-Token'] = window.csrfToken;
            }

            if (data) {
                options.body = JSON.stringify(data);
            }

            try {
                const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
                
                if (!response.ok) {
                    if (response.status === 401 || response.status === 403) {
                        await redirectToLogin(response.status === 401 ? 'Session expired. Please login again.' : 'Access denied. Admin privileges required.');
                        throw new Error('Authentication failed');
                    }
                    
                    let errorMessage = `HTTP error! status: ${response.status}`;
                    try {
                        const errorData = await response.json();
                        errorMessage = errorData.message || errorMessage;
                    } catch (e) {
                        // If response is not JSON, use default error message
                    }
                    throw new Error(errorMessage);
                }
                
                return await response.json();
            } catch (error) {
                console.error('API call failed:', error);
                
                if (error.message.includes('fetch')) {
                    throw new Error('Cannot connect to server. Please check if the server is running.');
                }
                
                throw error;
            }
        }

        function showAlert(message, type = 'error') {
            alertElement.textContent = message;
            alertElement.className = `alert ${type} show`;
            
            if (type === 'success') {
                setTimeout(() => {
                    alertElement.classList.remove('show');
                }, 3000);
            }
        }

        function hideAlert() {
            alertElement.classList.remove('show');
        }

        // Load all applications
        async function loadApplications() {
            try {
                appGrid.innerHTML = '<div class="loading show"><div class="spinner"></div><p>Loading applications...</p></div>';
                
                const result = await apiCall('/applications');
                applications = result.data || result || [];
                
                renderApplicationGrid();
                
            } catch (error) {
                console.error('Error loading applications:', error);
                showAlert('Failed to load applications: ' + error.message);
                appGrid.innerHTML = '<div style="padding: 20px; text-align: center; color: #dc3545;">Failed to load applications</div>';
            }
        }

        // Render application grid
        function renderApplicationGrid() {
            if (applications.length === 0) {
                appGrid.innerHTML = '<div style="padding: 20px; text-align: center; color: #6c757d;">No applications found</div>';
                return;
            }

            // Sort by application_name
            applications.sort((a, b) => (a.application_name || '').localeCompare(b.application_name || ''));

            const gridHTML = applications.map(app => `
                <div class="app-item" data-app-id="${app.application_id}" onclick="selectApplication(${app.application_id})">
                    <div class="name">${app.application_name || 'Unnamed Application'}</div>
                </div>
            `).join('');
            
            appGrid.innerHTML = gridHTML;
        }

        // Load all users for dropdown
        async function loadUsers() {
            try {
                const result = await apiCall('/users');
                users = result.data || result || [];
                
                // Sort by first_name, last_name
                users.sort((a, b) => {
                    const nameA = `${a.first_name || ''} ${a.last_name || ''}`.trim();
                    const nameB = `${b.first_name || ''} ${b.last_name || ''}`.trim();
                    return nameA.localeCompare(nameB);
                });

                // Populate user dropdown
                userSelect.innerHTML = '<option value="">Select a user...</option>';
                users.forEach(user => {
                    const fullName = `${user.first_name || ''} ${user.last_name || ''}`.trim();
                    userSelect.innerHTML += `<option value="${user.user_id}">${fullName}</option>`;
                });
                
            } catch (error) {
                console.error('Error loading users:', error);
                showAlert('Failed to load users: ' + error.message);
            }
        }

        // Select application
        async function selectApplication(applicationId) {
            try {
                // Update grid selection
                document.querySelectorAll('.app-item').forEach(item => {
                    item.classList.remove('selected');
                });
                document.querySelector(`[data-app-id="${applicationId}"]`).classList.add('selected');

                // Show loading
                formLoading.style.display = 'block';
                formContainer.style.display = 'none';

                // Load application details
                const appResult = await apiCall(`/applications/${applicationId}`);
                selectedApplication = appResult.data || appResult;

                // Load application users
                await loadApplicationUsers(applicationId);

                // Populate form
                appDescription.value = selectedApplication.description || '';
                
                // Populate app role dropdown from security_roles
                populateAppRoleDropdown(selectedApplication.security_roles);
                
                // Show form and enable buttons
                formLoading.style.display = 'none';
                formContainer.style.display = 'block';
                assignBtn.disabled = false;

                hideAlert();

            } catch (error) {
                console.error('Error loading application:', error);
                formLoading.style.display = 'none';
                showAlert('Failed to load application details: ' + error.message);
            }
        }

        // Load users assigned to application
        async function loadApplicationUsers(applicationId) {
            try {
                const result = await apiCall(`/app-users/${applicationId}`);
                appUsers = result.data || result || [];
                
                renderUserGrid();
                
            } catch (error) {
                console.error('Error loading application users:', error);
                appUsers = [];
                renderUserGrid();
            }
        }

        // Render user grid
        function renderUserGrid() {
            if (appUsers.length === 0) {
                userGrid.innerHTML = '<div style="padding: 20px; text-align: center; color: #6c757d;">No users assigned to this application</div>';
                return;
            }

            const gridHTML = appUsers.map(appUser => {
                const fullName = `${appUser.first_name || ''} ${appUser.last_name || ''}`.trim();
                return `
                    <div class="user-item" data-user-id="${appUser.user_id}" onclick="selectAppUser(${appUser.user_id})">
                        ${fullName} - ${appUser.status || 'Unknown'}
                    </div>
                `;
            }).join('');
            
            userGrid.innerHTML = gridHTML;
        }

        // Select application user
        function selectAppUser(userId) {
            // Update grid selection
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('selected');
            });
            document.querySelector(`[data-user-id="${userId}"]`).classList.add('selected');

            // Find selected app user
            selectedAppUser = appUsers.find(au => au.user_id === userId);
            
            if (selectedAppUser) {
                // Set current app_user_id for update mode
                currentAppUserId = selectedAppUser.app_user_id || userId;
                
                // Find the user to check if it's SAAdmin
                const user = users.find(u => u.user_id === selectedAppUser.user_id);
                const isSAAdmin = user && user.username === 'SAAdmin';
                
                // Populate form with selected user data
                userSelect.value = selectedAppUser.user_id;
                appRoleSelect.value = selectedAppUser.app_role || '';
                statusSelect.value = selectedAppUser.status || 'Inactive';
                trackUserSelect.value = selectedAppUser.track_user || 'No';
                startDate.value = selectedAppUser.start_date ? selectedAppUser.start_date.split('T')[0] : '';
                endDate.value = selectedAppUser.end_date ? selectedAppUser.end_date.split('T')[0] : '';
                
                // Apply SAAdmin restrictions
                if (isSAAdmin) {
                    // Disable all fields except status
                    userSelect.disabled = true;
                    appRoleSelect.disabled = true;
                    trackUserSelect.disabled = true;
                    startDate.disabled = true;
                    endDate.disabled = true;
                    
                    // Disable Add and Delete buttons, enable Submit and Cancel
                    assignBtn.disabled = true;
                    removeBtn.disabled = true;
                    updateBtn.disabled = false;
                    cancelBtn.disabled = false;
                } else {
                    // Enable all fields for non-SAAdmin users
                    userSelect.disabled = false;
                    appRoleSelect.disabled = false;
                    trackUserSelect.disabled = false;
                    
                    // Enable/disable date fields based on status
                    toggleDateFields();
                    
                    // Enable buttons normally
                    removeBtn.disabled = false;
                    updateBtn.disabled = false;
                }
            }
        }

        // Populate app role dropdown from security_roles
        function populateAppRoleDropdown(securityRoles) {
            appRoleSelect.innerHTML = '<option value="">Select a role...</option>';
            
            if (securityRoles && securityRoles.trim()) {
                const roles = securityRoles.split(',').map(role => role.trim()).filter(role => role);
                roles.forEach(role => {
                    appRoleSelect.innerHTML += `<option value="${role}">${role}</option>`;
                });
            }
        }

        // Toggle date fields based on status
        function toggleDateFields() {
            const isTemp = statusSelect.value === 'Temp Use';
            startDate.disabled = !isTemp;
            endDate.disabled = !isTemp;
            
            if (!isTemp) {
                startDate.value = '';
                endDate.value = '';
            }
        }

        // Event listeners
        statusSelect.addEventListener('change', toggleDateFields);

        // Add button - start new record process (does not save)
        assignBtn.addEventListener('click', () => {
            // Clear form and start new record mode
            selectedAppUser = null;
            userSelect.value = '';
            appRoleSelect.value = '';
            statusSelect.value = 'Inactive';
            trackUserSelect.value = 'No';
            startDate.value = '';
            endDate.value = '';
            currentAppUserId = 0;
            removeBtn.disabled = true;
            updateBtn.disabled = false;
            toggleDateFields();
            
            // Clear user grid selection
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('selected');
            });
            
            hideAlert();
        });

        // Remove user from application
        removeBtn.addEventListener('click', async () => {
            if (!selectedAppUser) {
                showAlert('No user selected for removal');
                return;
            }

            const result = await acm_SecurePopUp('Are you sure you want to remove this user from the application?', 'Yes:yes', 'No:no');
            if (result !== 'yes') {
                return;
            }

            try {
                await apiCall(`/app-users/${selectedApplication.application_id}/${selectedAppUser.user_id}`, 'DELETE');
                
                showAlert('User removed successfully', 'success');
                
                // Reload application users
                await loadApplicationUsers(selectedApplication.application_id);
                
                // Clear selection and form
                selectedAppUser = null;
                userSelect.value = '';
                statusSelect.value = 'Inactive';
                trackUserSelect.value = 'No';
                startDate.value = '';
                endDate.value = '';
                currentAppUserId = 0;
                removeBtn.disabled = true;
                updateBtn.disabled = true;
                toggleDateFields();

            } catch (error) {
                console.error('Error removing user:', error);
                showAlert('Failed to remove user: ' + error.message);
            }
        });

        // Submit - create new or update existing record
        updateBtn.addEventListener('click', async () => {
            try {
                const userId = userSelect.value;
                const status = statusSelect.value;
                
                if (!userId) {
                    showAlert('Please select a user');
                    return;
                }

                if (!selectedApplication) {
                    showAlert('No application selected');
                    return;
                }

                // Validate dates if both are provided
                if (status === 'Temp Use' && startDate.value && endDate.value) {
                    if (new Date(startDate.value) >= new Date(endDate.value)) {
                        showAlert('Start date must be before end date');
                        return;
                    }
                }

                const data = {
                    application_id: selectedApplication.application_id,
                    user_id: parseInt(userId),
                    app_role: appRoleSelect.value,
                    status: status,
                    track_user: trackUserSelect.value
                };

                if (status === 'Temp Use') {
                    if (startDate.value) data.start_date = startDate.value;
                    if (endDate.value) data.end_date = endDate.value;
                }

                if (currentAppUserId === 0) {
                    // Create new record
                    await apiCall('/app-users', 'POST', data);
                    showAlert('User assignment created successfully', 'success');
                } else {
                    // Update existing record
                    await apiCall(`/app-users/${selectedApplication.application_id}/${userId}`, 'PUT', data);
                    showAlert('User assignment updated successfully', 'success');
                }
                
                // Reload application users
                await loadApplicationUsers(selectedApplication.application_id);
                
                // Clear selection
                selectedAppUser = null;
                userSelect.value = '';
                appRoleSelect.value = '';
                statusSelect.value = 'Inactive';
                trackUserSelect.value = 'No';
                startDate.value = '';
                endDate.value = '';
                currentAppUserId = 0;
                removeBtn.disabled = true;
                updateBtn.disabled = true;
                toggleDateFields();

            } catch (error) {
                console.error('Error submitting user assignment:', error);
                showAlert('Failed to submit user assignment: ' + error.message);
            }
        });

        // Cancel button - clear form
        cancelBtn.addEventListener('click', () => {
            // Clear selection and form
            selectedAppUser = null;
            userSelect.value = '';
            appRoleSelect.value = '';
            statusSelect.value = 'Inactive';
            trackUserSelect.value = 'No';
            startDate.value = '';
            endDate.value = '';
            currentAppUserId = 0;
            removeBtn.disabled = true;
            updateBtn.disabled = true;
            toggleDateFields();
            
            // Clear user grid selection
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('selected');
            });
            
            hideAlert();
        });

        // Return to admin page
        returnBtn.addEventListener('click', () => {
            window.location.href = 'admin-page.html';
        });

        // Initialize the application
        document.addEventListener('DOMContentLoaded', async () => {
            console.log('Application Users Page initialized');
            
            // Fetch CSRF token
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
            
            // Check authentication
            const sessionId = localStorage.getItem('adminSessionId');
            if (!sessionId) {
                redirectToLogin('No admin session found. Please login.');
                return;
            }

            // Load data
            await Promise.all([
                loadApplications(),
                loadUsers()
            ]);
        });

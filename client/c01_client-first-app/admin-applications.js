        let API_BASE_URL = window.FVARS.SECURE_API_URL;
        
        // State management
        let applications = [];
        let selectedApplication = null;
        let isEditing = false;
        let isNewApplication = false;

        // DOM elements
        const appGrid = document.getElementById('appGrid');
        const formContainer = document.getElementById('formContainer');
        const formLoading = document.getElementById('formLoading');
        const applicationForm = document.getElementById('applicationForm');
        const alertElement = document.getElementById('alert');
        const addAppBtn = document.getElementById('addAppBtn');
        const deleteBtn = document.getElementById('deleteBtn');
        const submitBtn = document.getElementById('submitBtn');
        const cancelBtn = document.getElementById('cancelBtn');
        const returnBtn = document.getElementById('returnBtn');

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

        // API functions with session authentication
        async function apiCall(endpoint, method = 'GET', data = null) {
            // Validate endpoint to prevent SSRF
            if (!endpoint || typeof endpoint !== 'string' || !endpoint.startsWith('/')) {
                throw new Error('Invalid API endpoint');
            }
            
            // Prevent path traversal and protocol injection
            if (endpoint.includes('..') || endpoint.includes('//') || endpoint.includes('\\')) {
                throw new Error('Invalid API endpoint');
            }
            
            // Prevent encoded characters that could bypass validation
            if (endpoint.includes('%') || endpoint.includes('@')) {
                throw new Error('Invalid API endpoint');
            }
            
            const sessionId = localStorage.getItem('adminSessionId');
            
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
                const baseUrl = new URL(API_BASE_URL);
                
                // Construct URL safely using URL constructor
                const url = new URL(endpoint, API_BASE_URL);
                
                // Validate URL stays within API domain (origin and hostname)
                if (url.origin !== baseUrl.origin || url.hostname !== baseUrl.hostname) {
                    throw new Error('Invalid API endpoint');
                }
                
                // Validate protocol is http or https only
                if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                    throw new Error('Invalid protocol');
                }
                
                // Additional check: prevent access to internal networks and localhost
                if (isInternalIP(url.hostname) && !isInternalIP(baseUrl.hostname)) {
                    throw new Error('Access to internal networks is not allowed');
                }
                
                const response = await fetch(url.href, options);
                
                // Reject redirects to prevent SSRF
                if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
                    throw new Error('Redirects are not allowed');
                }
                
                if (!response.ok) {
                    if (response.status === 401) {
                        redirectToLogin('Session expired. Please login again.');
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
                
                if (error.message.includes('fetch')) {
                    throw new Error('Cannot connect to server. Please check if the server is running.');
                }
                
                throw error;
            }
        }

        // State for alert timeout
        let alertTimeout = null;

        function showAlert(message, type = 'error') {
            // Clear any existing timeout
            if (alertTimeout) {
                clearTimeout(alertTimeout);
                alertTimeout = null;
            }
            
            alertElement.textContent = message;
            alertElement.className = `alert ${type} show`;
            
            if (type === 'success') {
                alertTimeout = setTimeout(() => {
                    alertElement.classList.remove('show');
                    alertTimeout = null;
                }, 3000);
            }
        }

        function hideAlert() {
            if (alertTimeout) {
                clearTimeout(alertTimeout);
                alertTimeout = null;
            }
            alertElement.classList.remove('show');
        }

        /*
        // Open application URL in new tab
        function openApplicationURL() {
            const url = document.getElementById('applicationURL').value.trim();
            if (url) {
                // Add protocol if missing
                const fullUrl = url.startsWith('http') ? url : 'https://' + url;
                window.open(fullUrl, '_blank');
            } else {
                showAlert('Please enter a URL first');
            }
        }
        */

        // Validate URL against trusted domains
        function isUrlTrusted(urlString) {
            try {
                const url = new URL(urlString);
                const trustedDomains = [
                    'localhost',
                    '127.0.0.1',
                    'secureaccess247.com'
                ];
                return trustedDomains.some(domain => 
                    url.hostname === domain || url.hostname.endsWith('.' + domain)
                );
            } catch {
                return false;
            }
        }

        // Open redirect URL in new tab
        async function openRedirectURL() {
            const url = document.getElementById('redirectURL').value.trim();
            if (url) {
                try {
                    const urlObj = new URL(url.startsWith('http') ? url : 'https://' + url);
                    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
                        showAlert('Invalid URL protocol');
                        return;
                    }
                    
                    if (!isUrlTrusted(urlObj.href)) {
                        showAlert('URL domain is not in the trusted list');
                        return;
                    }
                    
                    const result = await acm_SecurePopUp(`Open URL: ${urlObj.href}?`, 'Yes:yes', 'No:no');
                    if (result === 'yes') {
                        window.open(urlObj.href, '_blank', 'noopener,noreferrer');
                    }
                } catch (e) {
                    const errorMessage = e && e.message ? e.message : 'Unknown error';
                    console.error('Invalid URL format:', errorMessage);
                    showAlert('Invalid URL format');
                }
            } else {
                showAlert('Please enter a redirect URL first');
            }
        }

        // Open failure URL in new tab
        async function openFailureURL() {
            const url = document.getElementById('failureURL').value.trim();
            if (url) {
                try {
                    const urlObj = new URL(url.startsWith('http') ? url : 'https://' + url);
                    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
                        showAlert('Invalid URL protocol');
                        return;
                    }
                    
                    if (!isUrlTrusted(urlObj.href)) {
                        showAlert('URL domain is not in the trusted list');
                        return;
                    }
                    
                    const result = await acm_SecurePopUp(`Open URL: ${urlObj.href}?`, 'Yes:yes', 'No:no');
                    if (result === 'yes') {
                        window.open(urlObj.href, '_blank', 'noopener,noreferrer');
                    }
                } catch (e) {
                    const errorMessage = e && e.message ? e.message : 'Unknown error';
                    console.error('Invalid URL format:', errorMessage);
                    showAlert('Invalid URL format');
                }
            } else {
                showAlert('Please enter a failure URL first');
            }
        }

        // Load all applications
        async function loadApplications() {
            try {
                appGrid.innerHTML = '<div class="loading show"><div class="spinner"></div><p>Loading applications...</p></div>';
                
                const result = await apiCall('/api/applications');
                
                applications = result.data || result || [];
                
                // Sort by application_name once when loading
                applications.sort((a, b) => (a.application_name || '').localeCompare(b.application_name || ''));
                
                renderApplicationGrid();
                
            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('❌ Error loading applications:', errorMessage);
                showAlert('Failed to load applications: ' + errorMessage);
                appGrid.innerHTML = '<div style="padding: 20px; text-align: center; color: #dc3545;">Failed to load applications</div>';
            }
        }

        // Render application grid
        function renderApplicationGrid() {
            if (applications.length === 0) {
                appGrid.innerHTML = '<div style="padding: 20px; text-align: center; color: #6c757d;">No applications found</div>';
                return;
            }

            appGrid.innerHTML = '';
            applications.forEach(app => {
                const appItem = document.createElement('div');
                appItem.className = 'app-item';
                appItem.setAttribute('data-app-id', app.application_id);
                appItem.onclick = () => selectApplication(app.application_id);
                
                const nameDiv = document.createElement('div');
                nameDiv.className = 'name';
                nameDiv.textContent = app.application_name || 'Unnamed Application';
                
                appItem.appendChild(nameDiv);
                appGrid.appendChild(appItem);
            });
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
                const result = await apiCall(`/api/applications/${applicationId}`);
                selectedApplication = result.data || result;

                populateForm(selectedApplication);
                
                // Show form and enable buttons
                formLoading.style.display = 'none';
                formContainer.style.display = 'block';
                deleteBtn.disabled = false;
                submitBtn.disabled = false;
                isEditing = false;
                isNewApplication = false;

                hideAlert();

            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Error loading application:', errorMessage);
                formLoading.style.display = 'none';
                showAlert('Failed to load application details: ' + errorMessage);
            }
        }

        // Generate random 20-character app key
        function generateAppKey() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const result = [];
            const randomValues = new Uint8Array(20);
            crypto.getRandomValues(randomValues);
            for (let i = 0; i < 20; i++) {
                result.push(chars.charAt(randomValues[i] % chars.length));
            }
            return result.join('');
        }

        // Decode HTML entities
        function decodeHtml(html) {
            if (!html) return html;
            return html
                .replace(/&#x2F;/g, '/')
                .replace(/&amp;/g, '&')
                .replace(/&lt;/g, '<')
                .replace(/&gt;/g, '>')
                .replace(/&quot;/g, '"')
                .replace(/&#39;/g, "'");
        }

        // Populate form with application data
        function populateForm(app) {
            document.getElementById('applicationName').value = app.application_name || '';
            document.getElementById('description').value = app.description || '';
            document.getElementById('redirectURL').value = decodeHtml(app.redirect_URL || '');
            document.getElementById('failureURL').value = decodeHtml(app.failure_URL || '');
            document.getElementById('securityRoles').value = app.security_roles || '';
            document.getElementById('parmEmail').value = app.parm_email || 'No';
            document.getElementById('parmUsername').value = app.parm_username || 'No';
            document.getElementById('parmPKCE').value = app.parm_PKCE || 'No';
            document.getElementById('status').value = app.status || 'Inactive';
            
            // Populate app key and other fields
            document.getElementById('appKey').value = app.app_key || '';
            document.getElementById('dateCreated').textContent = app.date_created ? new Date(app.date_created).toLocaleString() : '-';
            document.getElementById('dateUpdated').textContent = app.date_updated ? new Date(app.date_updated).toLocaleString() : '-';
        }

        // New App Key button handler
        document.getElementById('newAppKeyBtn').addEventListener('click', () => {
            document.getElementById('appKey').value = generateAppKey();
            isEditing = true;
        });

        // Add new application
        addAppBtn.addEventListener('click', () => {
            // Clear selection
            document.querySelectorAll('.app-item').forEach(item => {
                item.classList.remove('selected');
            });

            // Clear form
            applicationForm.reset();
            document.getElementById('status').value = 'Inactive';
            document.getElementById('parmEmail').value = 'No';
            document.getElementById('parmUsername').value = 'No';
            document.getElementById('parmPKCE').value = 'No';

            // Show form
            formContainer.style.display = 'block';
            formLoading.style.display = 'none';

            // Update state and buttons
            selectedApplication = null;
            isNewApplication = true;
            isEditing = true;
            deleteBtn.disabled = true;
            submitBtn.disabled = false;

            hideAlert();
            document.getElementById('applicationName').focus();
        });

        // Submit changes
        submitBtn.addEventListener('click', async () => {
            try {
                const applicationName = document.getElementById('applicationName').value.trim();
                
                if (!applicationName) {
                    showAlert('Application Name is required');
                    return;
                }

                const redirectURL = decodeHtml(document.getElementById('redirectURL').value);
                const failureURL = decodeHtml(document.getElementById('failureURL').value);

                const applicationData = {
                    application_name: applicationName,
                    description: document.getElementById('description').value.trim(),
                    redirect_URL: redirectURL.trim(),
                    failure_URL: failureURL.trim(),
                    app_key: document.getElementById('appKey').value.trim(),
                    security_roles: document.getElementById('securityRoles').value.trim(),
                    parm_email: document.getElementById('parmEmail').value,
                    parm_username: document.getElementById('parmUsername').value,
                    parm_PKCE: document.getElementById('parmPKCE').value,
                    status: document.getElementById('status').value
                };

                let result;
                if (isNewApplication) {
                    // Generate app key for new application if not already set
                    if (!applicationData.app_key) {
                        applicationData.app_key = generateAppKey();
                    }
                    result = await apiCall('/api/applications', 'POST', applicationData);
                    showAlert('Application created successfully', 'success');
                } else {
                    result = await apiCall(`/api/applications/${selectedApplication.application_id}`, 'PUT', applicationData);
                    showAlert('Application updated successfully', 'success');
                }

                // Reload applications list
                await loadApplications();
                
                if (isNewApplication) {
                    const newAppId = result.data?.application_id || result.application_id;
                    if (newAppId) {
                        setTimeout(() => selectApplication(newAppId), 500);
                    } else {
                        formContainer.style.display = 'none';
                        selectedApplication = null;
                        deleteBtn.disabled = true;
                        submitBtn.disabled = true;
                    }
                } else {
                    if (selectedApplication && selectedApplication.application_id) {
                        setTimeout(() => selectApplication(selectedApplication.application_id), 500);
                    }
                }

                isEditing = false;
                isNewApplication = false;

            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Error saving application:', errorMessage);
                showAlert('Failed to save application: ' + errorMessage);
            }
        });

        // Delete application
        deleteBtn.addEventListener('click', async () => {
            if (!selectedApplication || !selectedApplication.application_id) {
                showAlert('No application selected for deletion');
                return;
            }

            const delete_respond = await acm_SecurePopUp('Do you want to delete this application?', 'Yes:yes', 'No:no');
            
            if (delete_respond !== 'yes') {
                return;
            }
            


            try {
                await apiCall(`/api/applications/${selectedApplication.application_id}`, 'DELETE');
                
                showAlert('Application deleted successfully', 'success');
                
                // Reset form and reload applications
                formContainer.style.display = 'none';
                selectedApplication = null;
                deleteBtn.disabled = true;
                submitBtn.disabled = true;
                
                await loadApplications();

            } catch (error) {
                const errorMessage = error && error.message ? error.message : 'Unknown error';
                console.error('Error deleting application:', errorMessage);
                showAlert('Failed to delete application: ' + errorMessage);
            }
        });

        // Cancel changes
        cancelBtn.addEventListener('click', async () => {
            if (isEditing && (isNewApplication || selectedApplication)) {
                const result = await acm_SecurePopUp('Are you sure you want to cancel? All unsaved changes will be lost.', 'Yes:yes', 'No:no');
                if (result !== 'yes') {
                    return;
                }
            }

            if (selectedApplication && !isNewApplication) {
                populateForm(selectedApplication);
            } else {
                formContainer.style.display = 'none';
                document.querySelectorAll('.app-item').forEach(item => {
                    item.classList.remove('selected');
                });
                selectedApplication = null;
                deleteBtn.disabled = true;
                submitBtn.disabled = true;
            }

            isEditing = false;
            isNewApplication = false;
            hideAlert();
        });

        // Return to admin page
        returnBtn.addEventListener('click', () => {
            window.location.href = 'admin-page.html';
        });

        // Enable form change tracking
        applicationForm.addEventListener('input', () => {
            isEditing = true;
        });

        // Initialize the application
        document.addEventListener('DOMContentLoaded', async () => {
            console.log('Applications Page initialized');
            
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
            
            // Check authentication and load applications
            const sessionId = localStorage.getItem('adminSessionId');
            if (!sessionId) {
                redirectToLogin('No admin session found. Please login.');
                return;
            }

            await loadApplications();
        });

/**
 * Application Title Configuration
 * Change this constant to customize the title for all popup dialogs
 */
const ACM_APP_TITLE = 'SecureAccess';

// Cache for style elements to avoid repeated DOM queries
let popupStylesAdded = false;
let shakeStylesAdded = false;

/**
 * Secure Popup Function - acm_SecurePopUp
 * Creates a modal popup with customizable message and up to 10 buttons
 * Returns a Promise that resolves with the selected button's value
 * 
 * Usage: const result = await acm_SecurePopUp("Message", "Button1:Value1", "Button2:Value2", ...);
 */

window.acm_SecurePopUp = function acm_SecurePopUp(message, ...buttonDefinitions) {
    return new Promise((resolve, reject) => {
        // Use configurable app title
        const WindowCaption = ACM_APP_TITLE;
        // Input validation and security checks
        if (typeof message !== 'string' || message.trim() === '') {
            reject(new Error('Message must be a non-empty string'));
            return;
        }

        // Limit to 10 buttons for usability and security
        if (buttonDefinitions.length === 0) {
            reject(new Error('At least one button must be defined'));
            return;
        }

        if (buttonDefinitions.length > 10) {
            reject(new Error('Maximum 10 buttons allowed'));
            return;
        }
        // Parse and validate button definitions
        const buttons = [];

        for (let i = 0; i < buttonDefinitions.length; i++) {
            const buttonDef = buttonDefinitions[i];
            
            if (typeof buttonDef !== 'string') {
                reject(new Error(`Button definition ${i + 1} must be a string`));
                return;
            }

            // Parse button format "Label : Value"
            const parts = buttonDef.split(':');
            if (parts.length !== 2) {
                reject(new Error(`Invalid button format at position ${i + 1}. Use "Label : Value"`));
                return;
            }

            const label = parts[0].trim();
            const value = parts[1].trim();

            // Security: Validate label and value
            if (label === '' || value === '') {
                reject(new Error(`Button label and value cannot be empty at position ${i + 1}`));
                return;
            }

            // Prevent XSS by limiting allowed characters in labels
            if (!/^[\w\s\-.,!?()]+$/.test(label)) {
                reject(new Error(`Button label contains invalid characters at position ${i + 1}`));
                return;
            }

            buttons.push({ label, value });
        }

        // Create modal elements
        const overlay = document.createElement('div');
        const modal = document.createElement('div');
        const titleDiv = document.createElement('div');
        const messageDiv = document.createElement('div');
        const buttonsContainer = document.createElement('div');

        // Set up overlay (backdrop)
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
        `;

        // Set up modal
        modal.style.cssText = `
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            min-width: 300px;
            padding: 0;
            margin: 20px;
            max-height: 80vh;
            overflow: hidden;
            animation: acmPopupFadeIn 0.2s ease-out;
        `;

        // Set up title area (use WindowCaption)
        const displayTitle = WindowCaption;
        titleDiv.style.cssText = `
            padding: 20px 24px 12px 24px;
            font-size: 18px;
            font-weight: bold;
            color: #333;
            border-bottom: 1px solid #eee;
            background: #e3f2fd;
        `;
        titleDiv.textContent = displayTitle;

        // Set up message area
        messageDiv.style.cssText = `
            padding: 16px 24px;
            font-size: 16px;
            line-height: 1.5;
            color: #333;
            word-wrap: break-word;
        `;

        // Security: Sanitize message content to prevent XSS
        if (message.length > 1000) {
            message = message.substring(0, 1000);
        }
        messageDiv.textContent = message;

        // Set up buttons container
        buttonsContainer.style.cssText = `
            padding: 16px 24px 24px 24px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: flex-end;
        `;

        // Create buttons
        buttons.forEach((button, index) => {
            const btn = document.createElement('button');
            btn.textContent = button.label; // Security: Use textContent to prevent XSS
            btn.setAttribute('data-value', button.value);
            btn.setAttribute('type', 'button'); // Prevent form submission
            
            btn.style.cssText = `
                background: ${index === 0 ? '#007bff' : '#6c757d'};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                min-width: 70px;
                transition: background-color 0.2s;
            `;

            // Hover effects
            btn.addEventListener('mouseenter', () => {
                btn.style.backgroundColor = index === 0 ? '#0056b3' : '#545b62';
            });

            btn.addEventListener('mouseleave', () => {
                btn.style.backgroundColor = index === 0 ? '#007bff' : '#6c757d';
            });

            // Click handler
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const selectedValue = btn.getAttribute('data-value');
                cleanup();
                resolve(selectedValue);
            });

            buttonsContainer.appendChild(btn);
        });

        // Add CSS animation
        if (!popupStylesAdded) {
            const style = document.createElement('style');
            style.id = 'acm-popup-styles';
            style.textContent = `
                @keyframes acmPopupFadeIn {
                    from { opacity: 0; transform: scale(0.9); }
                    to { opacity: 1; transform: scale(1); }
                }
            `;
            document.head.appendChild(style);
            popupStylesAdded = true;
        }

        // Cleanup function
        function cleanup() {
            if (overlay && overlay.parentNode) {
                overlay.parentNode.removeChild(overlay);
            }
            // Remove event listeners
            document.removeEventListener('keydown', handleKeydown);
            window.removeEventListener('beforeunload', handleUnload);
        }

        // Handle escape key
        function handleKeydown(e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                cleanup();
                resolve(buttons[buttons.length - 1].value); // Return last button value on escape
            }
        }

        // Handle page unload
        function handleUnload() {
            cleanup();
            reject(new Error('Page unloaded'));
        }

        // Prevent overlay click from closing modal (security feature)
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                e.preventDefault();
                e.stopPropagation();
                // Optional: Add visual feedback that clicking outside doesn't close
                modal.style.animation = 'none';
                modal.offsetHeight; // Trigger reflow
                modal.style.animation = 'acmPopupShake 0.3s ease-in-out';
            }
        });

        // Add shake animation for invalid clicks
        if (!shakeStylesAdded) {
            const shakeStyle = document.createElement('style');
            shakeStyle.id = 'acm-popup-shake-styles';
            shakeStyle.textContent = `
                @keyframes acmPopupShake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-5px); }
                    75% { transform: translateX(5px); }
                }
            `;
            document.head.appendChild(shakeStyle);
            shakeStylesAdded = true;
        }

        // Assemble modal
        modal.appendChild(titleDiv);
        modal.appendChild(messageDiv);
        modal.appendChild(buttonsContainer);
        overlay.appendChild(modal);

        // Validate origin for security
        const allowedHosts = ['localhost', '127.0.0.1'];
        if (window.location.protocol !== 'https:' && !allowedHosts.includes(window.location.hostname)) {
            cleanup();
            reject(new Error('Insecure origin detected'));
            return;
        }
        
        // Add event listeners
        document.addEventListener('keydown', handleKeydown);
        window.addEventListener('beforeunload', handleUnload);

        // Add to DOM
        document.body.appendChild(overlay);

        // Focus first button for accessibility
        setTimeout(() => {
            const firstButton = buttonsContainer.querySelector('button');
            if (firstButton) {
                firstButton.focus();
            }
        }, 100);

        // Auto-cleanup after 5 minutes
        setTimeout(() => {
            cleanup();
            reject(new Error('Popup timeout'));
        }, 300000);
    });
}

/**
 * Secure Question Function - acm_SecureQuestion
 * Creates a modal popup with a question and secure text input
 * Returns a Promise that resolves with the sanitized user input
 * 
 * Usage: const answer = await acm_SecureQuestion("What is your favorite color?");
 */
window.acm_SecureQuestion = function acm_SecureQuestion(questionText) {
    return new Promise((resolve, reject) => {
        // Use configurable app title
        const WindowCaption = ACM_APP_TITLE;
        
        // Input validation
        if (typeof questionText !== 'string' || questionText.trim() === '') {
            reject(new Error('Question text must be a non-empty string'));
            return;
        }

        // Create modal elements
        const overlay = document.createElement('div');
        const modal = document.createElement('div');
        const titleDiv = document.createElement('div');
        const questionDiv = document.createElement('div');
        const inputDiv = document.createElement('div');
        const textInput = document.createElement('input');
        const buttonsContainer = document.createElement('div');

        // Set up overlay
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
        `;

        // Set up modal
        modal.style.cssText = `
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            min-width: 350px;
            padding: 0;
            margin: 20px;
            max-height: 80vh;
            overflow: hidden;
            animation: acmPopupFadeIn 0.2s ease-out;
        `;

        // Set up title
        titleDiv.style.cssText = `
            padding: 20px 24px 12px 24px;
            font-size: 18px;
            font-weight: bold;
            color: #333;
            border-bottom: 1px solid #eee;
            background: #e3f2fd;
        `;
        titleDiv.textContent = WindowCaption;

        // Set up question
        questionDiv.style.cssText = `
            padding: 16px 24px;
            font-size: 16px;
            line-height: 1.5;
            color: #333;
            word-wrap: break-word;
        `;
        questionDiv.textContent = questionText;

        // Set up input container
        inputDiv.style.cssText = `
            padding: 0 24px 16px 24px;
        `;

        // Set up secure text input
        textInput.type = 'text';
        textInput.style.cssText = `
            width: 100%;
            padding: 10px 12px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            outline: none;
            transition: border-color 0.2s;
        `;
        textInput.placeholder = 'Enter your answer...';
        
        // Input security and validation
        textInput.addEventListener('input', (e) => {
            let value = e.target.value;
            // Remove potentially harmful characters
            value = value.replace(/[<>"'&\x00-\x1f\x7f-\x9f]/g, '');
            // Limit length for security
            if (value.length > 500) {
                value = value.substring(0, 500);
            }
            e.target.value = value;
        });

        textInput.addEventListener('focus', () => {
            textInput.style.borderColor = '#007bff';
        });

        textInput.addEventListener('blur', () => {
            textInput.style.borderColor = '#ddd';
        });

        // Set up buttons
        buttonsContainer.style.cssText = `
            padding: 16px 24px 24px 24px;
            display: flex;
            gap: 8px;
            justify-content: flex-end;
        `;

        const submitBtn = document.createElement('button');
        submitBtn.textContent = 'Submit';
        submitBtn.style.cssText = `
            background: #007bff;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            min-width: 70px;
        `;

        const cancelBtn = document.createElement('button');
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.cssText = `
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            min-width: 70px;
        `;

        // Button handlers
        submitBtn.addEventListener('click', () => {
            const answer = textInput.value.trim();
            if (answer === '') {
                textInput.style.borderColor = '#dc3545';
                textInput.focus();
                return;
            }
            cleanup();
            resolve(answer);
        });

        cancelBtn.addEventListener('click', () => {
            cleanup();
            resolve(null);
        });

        // Enter key handler
        textInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                submitBtn.click();
            }
        });

        // Cleanup function
        function cleanup() {
            if (overlay && overlay.parentNode) {
                overlay.parentNode.removeChild(overlay);
            }
            document.removeEventListener('keydown', handleKeydown);
        }

        // Escape key handler
        function handleKeydown(e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                cleanup();
                resolve(null);
            }
        }

        // Assemble modal
        inputDiv.appendChild(textInput);
        buttonsContainer.appendChild(submitBtn);
        buttonsContainer.appendChild(cancelBtn);
        modal.appendChild(titleDiv);
        modal.appendChild(questionDiv);
        modal.appendChild(inputDiv);
        modal.appendChild(buttonsContainer);
        overlay.appendChild(modal);

        // Validate origin for security
        const allowedHosts = ['localhost', '127.0.0.1'];
        if (window.location.protocol !== 'https:' && !allowedHosts.includes(window.location.hostname)) {
            cleanup();
            reject(new Error('Insecure origin detected'));
            return;
        }
        
        // Add event listeners
        document.addEventListener('keydown', handleKeydown);

        // Add to DOM
        document.body.appendChild(overlay);

        // Focus input
        setTimeout(() => {
            textInput.focus();
        }, 100);

        // Auto-cleanup after 5 minutes
        setTimeout(() => {
            cleanup();
            reject(new Error('Question timeout'));
        }, 300000);
    });
}
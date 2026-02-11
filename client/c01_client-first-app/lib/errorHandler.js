/**
 * Client-side Error Handling Utility
 */

window.ErrorHandler = {
    /**
     * Handle and log errors consistently
     */
    handle(error, context, showAlert = false) {
        const errorMessage = error?.message || 'Unknown error';
        const timestamp = new Date().toISOString();
        
        console.error(`❌ [${timestamp}] Error in ${context}:`, errorMessage);
        
        if (showAlert) {
            alert(`Error: ${errorMessage}`);
        }
        
        return errorMessage;
    },

    /**
     * Handle fetch errors
     */
    async handleFetchError(response, context) {
        let errorMessage = `HTTP ${response.status}`;
        
        try {
            const data = await response.json();
            errorMessage = data.message || errorMessage;
        } catch (e) {
            console.error('Failed to parse error response:', e.message || 'Unknown error');
        }
        
        console.error(`❌ Error in ${context}:`, errorMessage);
        return errorMessage;
    },

    /**
     * Wrap async functions with error handling
     */
    async wrap(fn, context, showAlert = false) {
        try {
            return await fn();
        } catch (error) {
            this.handle(error, context, showAlert);
            throw error;
        }
    }
};

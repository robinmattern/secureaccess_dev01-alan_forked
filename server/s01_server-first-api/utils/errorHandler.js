/**
 * Centralized Error Handling Utility
 */

function handleError(error, res, context, statusCode = 500, userMessage = null) {
    const errorMessage = error?.message || 'Unknown error';
    const timestamp = new Date().toISOString();
    
    console.error(`❌ [${timestamp}] Error in ${context}:`, errorMessage);
    if (error?.stack) {
        console.error('Stack trace:', error.stack);
    }
    
    if (!res.headersSent) {
        res.status(statusCode).json({
            success: false,
            message: userMessage || `Failed to ${context}`,
            error: process.env.NODE_ENV === 'production' ? undefined : errorMessage
        });
    }
}

function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

function validateRequiredFields(body, requiredFields) {
    const missing = requiredFields.filter(field => !body[field]);
    return {
        valid: missing.length === 0,
        missing
    };
}

function safeJsonParse(jsonString, defaultValue = null) {
    try {
        return JSON.parse(jsonString);
    } catch (error) {
        console.error('JSON parse error:', error.message || 'Unknown error');
        return defaultValue;
    }
}

module.exports = {
    handleError,
    asyncHandler,
    validateRequiredFields,
    safeJsonParse
};

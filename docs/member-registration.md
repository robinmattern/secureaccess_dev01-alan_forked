# IODD Member Registration - SecureAccess Integration

## Overview

When a new member registers in the IODD application, the IODD server automatically creates a corresponding user account in SecureAccess via a secure server-to-server API call.

## Registration Flow

```
User → IODD Client → IODD Server → SecureAccess API
                         ↓
                    IODD Database
```

1. User fills out registration form on IODD website
2. IODD client validates input and sends to IODD server
3. IODD server validates, hashes sensitive data, creates IODD member account
4. IODD server calls SecureAccess API to create user account
5. User can now log in to IODD using SecureAccess authentication

---

## SecureAccess API Endpoint

### Endpoint Details

**URL:** `POST /api/register`

**Full URL:** `https://secureaccess247.com/api/register`

**Content-Type:** `application/json`

**Authentication:** API Key in header

---

## Request Format

### Headers

```
Content-Type: application/json
X-API-Key: <shared-secret-key>
```

The `X-API-Key` must match the secret configured in both applications.

### Request Body (JSON)

```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "username": "johndoe",
  "password": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "securityQuestion1": "What is your favorite color?",
  "securityAnswer1": "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
  "securityQuestion2": "What city were you born in?",
  "securityAnswer2": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
  "appKey": "ehYzQWxtl62vuPbUjDYU",
  "userRole": "Member"
}
```

---

## Field Descriptions

| Field | Type | Description | Format |
|-------|------|-------------|--------|
| `firstName` | String | User's first name | Plain text |
| `lastName` | String | User's last name | Plain text |
| `email` | String | User's email address | Plain text, validated |
| `username` | String | Chosen username | Plain text |
| `password` | String | User's password | **SHA-256 hashed** (64-char hex) |
| `securityQuestion1` | String | First security question | Plain text |
| `securityAnswer1` | String | Answer to first question | **SHA-256 hashed** (64-char hex) |
| `securityQuestion2` | String | Second security question | Plain text |
| `securityAnswer2` | String | Answer to second question | **SHA-256 hashed** (64-char hex) |
| `appKey` | String | IODD application identifier | Plain text (from config) |
| `userRole` | String | User's role in IODD | Always "Member" for new registrations |

---

## Security Notes

### Hashed Fields

The following fields are **SHA-256 hashed** before transmission:
- `password`
- `securityAnswer1`
- `securityAnswer2`

**Example:**
- Original password: `MyPassword123`
- Hashed value: `a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3`

### Plain Text Fields

The following fields are sent as **plain text**:
- `firstName`, `lastName`, `email`, `username`
- `securityQuestion1`, `securityQuestion2` (the questions themselves)
- `appKey`, `userRole`

### Authentication

The `X-API-Key` header contains a shared secret that both IODD and SecureAccess must know. This prevents unauthorized applications from creating accounts.

---

## SecureAccess Implementation

### Configuration Required

Add to SecureAccess `_config.js`:

```javascript
var _FVARS = {
  // ... other config ...
  "IODD_APP_KEY": "ehYzQWxtl62vuPbUjDYU",
  "API_SECRET": "your-shared-secret-key-here",
  "ALLOWED_APPS": ["IODD"]
}
```

### Sample Endpoint Handler

```javascript
// SecureAccess: /api/register endpoint

import crypto from 'crypto';

async function registerHandler(req, res) {
    try {
        // 1. Validate API Key
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== process.FVARS.API_SECRET) {
            return res.status(401).json({ 
                success: false, 
                message: 'Unauthorized' 
            });
        }

        // 2. Extract request data
        const {
            firstName,
            lastName,
            email,
            username,
            password,           // Already hashed by IODD
            securityQuestion1,
            securityAnswer1,    // Already hashed by IODD
            securityQuestion2,
            securityAnswer2,    // Already hashed by IODD
            appKey,
            userRole
        } = req.body;

        // 3. Validate app key
        if (appKey !== process.FVARS.IODD_APP_KEY) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid app key' 
            });
        }

        // 4. Validate required fields
        if (!firstName || !lastName || !email || !username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields' 
            });
        }

        // 5. Check if user already exists
        const existingUser = await db.query(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );

        if (existingUser.length > 0) {
            return res.status(409).json({ 
                success: false, 
                message: 'User already exists' 
            });
        }

        // 6. Create user account in SecureAccess database
        const userId = await db.query(
            `INSERT INTO users 
             (firstName, lastName, email, username, password, 
              securityQuestion1, securityAnswer1, 
              securityQuestion2, securityAnswer2, 
              createdAt, active) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), 1)`,
            [firstName, lastName, email, username, password,
             securityQuestion1, securityAnswer1,
             securityQuestion2, securityAnswer2]
        );

        // 7. Link user to IODD app
        await db.query(
            `INSERT INTO app_users (userId, appKey, appRole, createdAt) 
             VALUES (?, ?, ?, NOW())`,
            [userId, appKey, userRole]
        );

        // 8. Return success
        return res.json({ 
            success: true, 
            message: 'User created successfully',
            userId: userId
        });

    } catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Registration failed' 
        });
    }
}

export default registerHandler;
```

---

## Database Schema

### SecureAccess Tables Required

#### `users` table
```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    firstName VARCHAR(100),
    lastName VARCHAR(100),
    email VARCHAR(255) UNIQUE,
    username VARCHAR(100) UNIQUE,
    password VARCHAR(64),              -- SHA-256 hash
    securityQuestion1 TEXT,
    securityAnswer1 VARCHAR(64),       -- SHA-256 hash
    securityQuestion2 TEXT,
    securityAnswer2 VARCHAR(64),       -- SHA-256 hash
    active TINYINT DEFAULT 1,
    createdAt DATETIME,
    updatedAt DATETIME
);
```

#### `app_users` table (links users to apps)
```sql
CREATE TABLE app_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT,
    appKey VARCHAR(50),
    appRole VARCHAR(50),
    createdAt DATETIME,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

---

## Response Format

### Success Response

```json
{
  "success": true,
  "message": "User created successfully",
  "userId": 12345
}
```

**HTTP Status:** 200 OK

### Error Responses

#### Unauthorized (Invalid API Key)
```json
{
  "success": false,
  "message": "Unauthorized"
}
```
**HTTP Status:** 401 Unauthorized

#### Invalid App Key
```json
{
  "success": false,
  "message": "Invalid app key"
}
```
**HTTP Status:** 403 Forbidden

#### User Already Exists
```json
{
  "success": false,
  "message": "User already exists"
}
```
**HTTP Status:** 409 Conflict

#### Missing Fields
```json
{
  "success": false,
  "message": "Missing required fields"
}
```
**HTTP Status:** 400 Bad Request

#### Server Error
```json
{
  "success": false,
  "message": "Registration failed"
}
```
**HTTP Status:** 500 Internal Server Error

---

## Testing

### Generate Test Hash

To test with hashed values:

```javascript
const crypto = require('crypto');

function hashValue(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

console.log('Password hash:', hashValue('TestPassword123'));
console.log('Answer hash:', hashValue('blue'));
```

### Sample cURL Request

```bash
curl -X POST https://secureaccess247.com/api/register \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-shared-secret-key-here" \
  -d '{
    "firstName": "Test",
    "lastName": "User",
    "email": "test@example.com",
    "username": "testuser",
    "password": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
    "securityQuestion1": "What is your favorite color?",
    "securityAnswer1": "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
    "securityQuestion2": "What city were you born in?",
    "securityAnswer2": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    "appKey": "ehYzQWxtl62vuPbUjDYU",
    "userRole": "Member"
  }'
```

---

## Validation Checklist

SecureAccess should validate:

- [ ] `X-API-Key` header matches configured secret
- [ ] `appKey` matches IODD's app key
- [ ] All required fields are present
- [ ] Email format is valid
- [ ] Email is not already registered
- [ ] Username is not already taken
- [ ] Password is 64-character hex string (SHA-256 hash)
- [ ] Security answers are 64-character hex strings (SHA-256 hashes)

---

## Error Handling

### IODD Behavior

If SecureAccess API call fails:
- IODD member account is **still created**
- User can use IODD but cannot use SecureAccess authentication
- Error is logged on IODD server
- User sees success message (IODD account created)

### Recommended Approach

SecureAccess should:
1. Log all registration attempts
2. Return clear error messages
3. Prevent duplicate accounts (check email/username)
4. Handle database errors gracefully

---

## Security Considerations

1. **Never log passwords or security answers** (even hashed)
2. **Validate API key on every request**
3. **Use HTTPS only** in production
4. **Rate limit** the registration endpoint
5. **Store hashes as-is** (already hashed by IODD)
6. **Validate hash format** (64-char hex string)

---

## Configuration Summary

### IODD `_config.js`
```javascript
"SECURE_APP_KEY": "ehYzQWxtl62vuPbUjDYU"
"SECURE_API_URL": "https://secureaccess247.com/api"
"SECURE_API_SECRET": "your-shared-secret-key-here"
```

### SecureAccess `_config.js`
```javascript
"IODD_APP_KEY": "ehYzQWxtl62vuPbUjDYU"
"API_SECRET": "your-shared-secret-key-here"
"ALLOWED_APPS": ["IODD"]
```

**Important:** Both `SECURE_API_SECRET` and `API_SECRET` must be identical.

---

## Support

For questions or issues:
- IODD Server Code: `server3/s32_iodd-data-api/api/register-endpoint.js`
- IODD Client Code: `client3/c32_iodd-app/register.js`
- Security Documentation: `SECURITY.md`

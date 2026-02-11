# Security Features Documentation
## SecureAccess (SAS) - Comprehensive Security Implementation

**Version:** 1.02  
**Last Updated:** December 2024  
**Classification:** Internal Use

---

## Table of Contents
1. [Security Overview](#security-overview)
2. [Authentication](#authentication)
3. [Authorization](#authorization)
4. [Password Security](#password-security)
5. [Two-Factor Authentication](#two-factor-authentication)
6. [Session Management](#session-management)
7. [CSRF Protection](#csrf-protection)
8. [Rate Limiting](#rate-limiting)
9. [Input Validation](#input-validation)
10. [Data Protection](#data-protection)
11. [Security Monitoring](#security-monitoring)
12. [Compliance](#compliance)

---

## Security Overview

### Security Architecture
SecureAccess implements defense-in-depth security with multiple layers:

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Network Security (HTTPS, CORS, Firewall) │
├─────────────────────────────────────────────────────┤
│  Layer 2: Authentication (JWT, 2FA, Sessions)       │
├─────────────────────────────────────────────────────┤
│  Layer 3: Authorization (RBAC, Permissions)         │
├─────────────────────────────────────────────────────┤
│  Layer 4: Input Validation (Joi, Sanitization)      │
├─────────────────────────────────────────────────────┤
│  Layer 5: Data Protection (Encryption, Hashing)     │
├─────────────────────────────────────────────────────┤
│  Layer 6: Monitoring (Audit Logs, Rate Limiting)    │
└─────────────────────────────────────────────────────┘
```

### Security Principles
- **Least Privilege** - Users have minimum necessary permissions
- **Defense in Depth** - Multiple security layers
- **Fail Secure** - System fails to secure state
- **Zero Trust** - Verify every request
- **Audit Everything** - Comprehensive logging

---

## Authentication

### JWT (JSON Web Tokens)

#### Token Structure
```javascript
{
  "user_id": 123,
  "username": "john_doe",
  "email": "john@example.com",
  "role": "User",
  "account_status": "Active",
  "iat": 1640000000,
  "exp": 1640086400,
  "iss": "SecureAccess",
  "aud": "SecureAccess-Users"
}
```

#### Token Configuration
- **Algorithm:** HS256 (HMAC with SHA-256)
- **Secret:** 256-bit random key (environment variable)
- **Expiration:** 24 hours (configurable per user)
- **Storage:** HTTP-only cookies (not accessible via JavaScript)
- **Refresh:** Automatic token rotation on password change

#### Token Security Features
1. **HTTP-Only Cookies** - Prevents XSS attacks
2. **Secure Flag** - HTTPS only in production
3. **SameSite: Strict** - CSRF protection
4. **Version Control** - `jwt_secret_version` invalidates old tokens
5. **Signature Verification** - Prevents tampering

#### Implementation
```javascript
// Token Generation
const token = jwt.sign(payload, JWT_SECRET, {
  expiresIn: '24h',
  issuer: 'SecureAccess',
  audience: 'SecureAccess-Users'
});

// Token Storage
res.cookie('authToken', token, {
  httpOnly: true,
  secure: NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 24 * 60 * 60 * 1000,
  path: '/'
});
```

---

## Authorization

### Role-Based Access Control (RBAC)

#### Roles
| Role | Permissions | Description |
|------|-------------|-------------|
| **Admin** | Full access | Manage users, applications, settings |
| **User** | Limited access | View own profile, assigned applications |

#### Permission Matrix
| Resource | Admin | User |
|----------|-------|------|
| View all users | ✓ | ✗ |
| Create user | ✓ | ✗ |
| Update any user | ✓ | ✗ |
| Delete user | ✓ | ✗ |
| View own profile | ✓ | ✓ |
| Update own profile | ✓ | ✓ |
| View applications | ✓ | ✓ |
| Manage applications | ✓ | ✗ |

#### Middleware Implementation
```javascript
// Admin-only endpoint
app.get('/api/users', verifyToken, requireAdmin, getAllUsers);

// User or Admin endpoint
app.get('/api/users/me', verifyToken, authorize(['Admin', 'User']), getUserById);

// Self-service with ownership check
if (req.user.role !== 'Admin' && req.user.userId !== userId) {
  return res.status(403).json({ message: 'Access denied' });
}
```

---

## Password Security

### Password Requirements
- **Minimum Length:** 8 characters
- **Complexity:**
  - At least 1 uppercase letter (A-Z)
  - At least 1 lowercase letter (a-z)
  - At least 1 number (0-9)
  - At least 1 special character (!@#$%^&*(),.?":{}|<>)
  
### Password Hashing

#### Algorithm: bcrypt
- **Cost Factor:** 12 rounds (2^12 iterations)
- **Salt:** 32-byte random salt per password
- **Output:** 60-character hash

#### Implementation
```javascript
// Generate salt
const salt = crypto.randomBytes(32).toString('hex');

// Hash password with salt
const hash = await bcrypt.hash(password + salt, 12);

// Store both salt and hash
INSERT INTO sa_users (master_password_hash, salt) VALUES (?, ?);
```

#### Why bcrypt?
- **Adaptive:** Cost factor increases with hardware improvements
- **Salted:** Prevents rainbow table attacks
- **Slow:** Intentionally slow to prevent brute force
- **Industry Standard:** Widely tested and trusted

### Security Answers
Security answers use the same bcrypt hashing:
```javascript
const hashedAnswer = await bcrypt.hash(answer.toLowerCase().trim() + salt, 12);
```

**Note:** Answers are normalized (lowercase, trimmed) before hashing for consistency.

---

## Two-Factor Authentication

### 2FA Implementation

#### Method: Email-based TOTP
- **Code Length:** 8 digits
- **Generation:** Cryptographically secure random
- **Expiration:** 10 minutes
- **Delivery:** Email via SMTP

#### 2FA Flow
```
1. User enters username/password
2. System validates credentials
3. System generates 8-digit code
4. Code stored in Redis/memory with 10-min TTL
5. Code sent to user's email
6. User enters code
7. System validates code
8. Login successful
```

#### Code Generation
```javascript
const code = crypto.randomInt(10000000, 100000000).toString();
const expiresInSeconds = 10 * 60; // 10 minutes

await twoFactorStorage.set(
  `${userId}_${username}`, 
  { code, userId }, 
  expiresInSeconds
);
```

#### Storage Options
1. **Redis** (Production) - Distributed, persistent
2. **In-Memory** (Development) - Simple, no dependencies

#### Rate Limiting
- **Limit:** 5 attempts per 10 minutes per IP
- **Tracking:** In-memory Map with automatic cleanup
- **Response:** HTTP 429 (Too Many Requests)

### Backup Codes

#### Generation
- **Count:** 10 codes per user
- **Length:** 8 characters (hexadecimal)
- **Storage:** bcrypt hashed array in database
- **One-time Use:** Code removed after successful use

#### Implementation
```javascript
// Generate codes
const codes = [];
for (let i = 0; i < 10; i++) {
  codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
}

// Hash codes
const hashedCodes = await Promise.all(
  codes.map(code => bcrypt.hash(code, 12))
);

// Store in database
UPDATE sa_users SET backup_codes = ? WHERE user_id = ?;
```

---

## Session Management

### Session Storage
- **Primary:** HTTP-only cookies
- **Fallback:** localStorage (session IDs only)
- **Expiration:** 24 hours (configurable)

### Session Security
1. **HTTP-Only Cookies** - Not accessible via JavaScript
2. **Secure Flag** - HTTPS only in production
3. **SameSite: Strict** - Prevents CSRF
4. **Automatic Expiration** - Token expires after 24 hours
5. **Token Rotation** - New token on password change

### Session Invalidation
Sessions are invalidated when:
- Token expires (24 hours)
- User logs out
- Password is changed (`jwt_secret_version` incremented)
- Account is locked or disabled
- Admin manually revokes access

---

## CSRF Protection

### Double-Submit Cookie Pattern

#### How It Works
1. Server generates CSRF token
2. Token stored in cookie (`_csrf`)
3. Client reads token from cookie
4. Client sends token in header (`X-CSRF-Token`)
5. Server validates cookie matches header

#### Implementation
```javascript
// Server-side
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: false, // true in production
    sameSite: 'lax',
    path: '/'
  }
});

// Client-side
const token = await fetch('/csrf-token').then(r => r.json());
fetch('/api/users', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': token.csrfToken,
    'X-Requested-With': 'XMLHttpRequest'
  }
});
```

#### Additional Protection
- **X-Requested-With Header** - Must be `XMLHttpRequest`
- **Origin Validation** - Checks request origin
- **Referer Validation** - Validates referer header

---

## Rate Limiting

### Rate Limit Configuration

| Endpoint | Limit | Window | Action |
|----------|-------|--------|--------|
| Login | 5 attempts | 15 min | HTTP 429 |
| 2FA Verification | 5 attempts | 10 min | HTTP 429 |
| Password Reset | 3 attempts | 15 min | HTTP 429 |
| General API | 100 requests | 15 min | HTTP 429 |

### Account Lockout
- **Threshold:** 5 failed login attempts
- **Duration:** 30 minutes
- **Reset:** Automatic after duration
- **Notification:** Audit log entry
- **Override:** Admin can manually unlock

### Implementation
```javascript
const loginAttempts = new Map();

function rateLimitLogin(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxAttempts = 5;

  if (!loginAttempts.has(ip)) {
    loginAttempts.set(ip, { count: 0, resetTime: now + windowMs });
  }

  const attempts = loginAttempts.get(ip);

  if (now > attempts.resetTime) {
    attempts.count = 0;
    attempts.resetTime = now + windowMs;
  }

  if (attempts.count >= maxAttempts) {
    return res.status(429).json({
      message: 'Too many attempts. Try again later.'
    });
  }

  attempts.count++;
  next();
}
```

---

## Input Validation

### Validation Strategy
1. **Client-Side** - Immediate feedback (UX)
2. **Server-Side** - Security enforcement (required)
3. **Database** - Constraints and types (last line)

### Joi Validation Schemas

#### User Creation
```javascript
const createUserSchema = Joi.object({
  first_name: Joi.string().max(100).required(),
  last_name: Joi.string().max(100).required(),
  username: Joi.string().max(255).required(),
  email: Joi.string().email().max(255).required(),
  password: Joi.string().min(8).required(),
  two_factor_enabled: Joi.boolean().default(false)
});
```

#### User Update
```javascript
const updateUserSchema = Joi.object({
  first_name: Joi.string().max(100).optional(),
  email: Joi.string().email().max(255).optional(),
  password: Joi.string().min(8).optional(),
  account_status: Joi.string().valid('active', 'inactive', 'locked').optional()
});
```

### Input Sanitization
```javascript
// Remove dangerous characters
const sanitizeInput = (input) => {
  return input
    .replace(/[<>]/g, '') // Remove HTML tags
    .trim(); // Remove whitespace
};

// Validate email format
if (!validator.isEmail(email)) {
  return res.status(400).json({ message: 'Invalid email' });
}
```

### SQL Injection Prevention
**Always use parameterized queries:**
```javascript
// ✓ SAFE - Parameterized query
await pool.execute(
  'SELECT * FROM sa_users WHERE username = ?',
  [username]
);

// ✗ UNSAFE - String concatenation
await pool.execute(
  `SELECT * FROM sa_users WHERE username = '${username}'`
);
```

---

## Data Protection

### Encryption at Rest
- **Passwords:** bcrypt hashed (12 rounds)
- **Security Answers:** bcrypt hashed (12 rounds)
- **2FA Secrets:** Encrypted in database
- **Backup Codes:** bcrypt hashed array
- **Database:** MySQL encryption at rest (optional)

### Encryption in Transit
- **HTTPS:** TLS 1.2+ required in production
- **Certificate:** Valid SSL certificate
- **HSTS:** HTTP Strict Transport Security enabled
- **Secure Cookies:** Secure flag enabled in production

### Sensitive Data Handling
**Never log or expose:**
- Passwords (plain or hashed)
- Security answers
- JWT secrets
- API keys
- 2FA codes
- Backup codes

**Safe to log:**
- User IDs
- Usernames
- Email addresses (masked)
- Timestamps
- IP addresses (for security)

### Data Minimization
Only collect and store necessary data:
- ✓ Username, email, name
- ✓ Hashed passwords
- ✓ Security questions (not answers)
- ✗ Social security numbers
- ✗ Credit card numbers
- ✗ Unnecessary personal data

---

## Security Monitoring

### Audit Logging

#### Events Logged
- Login attempts (success/failure)
- 2FA code generation and verification
- Password changes
- Account lockouts
- Token generation and verification
- Admin actions
- Failed authorization attempts

#### Log Format
```javascript
{
  timestamp: "2024-12-01T12:00:00.000Z",
  event: "LOGIN_SUCCESS",
  userId: 123,
  username: "john_doe",
  ip: "192.168.1.1",
  userAgent: "Mozilla/5.0..."
}
```

#### Implementation
```javascript
security.auditLog('LOGIN_SUCCESS', {
  username,
  role: user.role,
  ip: req.ip
});
```

### Security Headers

#### Implemented Headers
```javascript
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});
```

### Error Handling
- **Production:** Generic error messages
- **Development:** Detailed error messages
- **Logging:** All errors logged with context
- **No Stack Traces:** Never expose to client

---

## Compliance

### OWASP Top 10 Protection

| Vulnerability | Protection |
|---------------|------------|
| A01: Broken Access Control | RBAC, JWT verification, ownership checks |
| A02: Cryptographic Failures | bcrypt, HTTPS, secure cookies |
| A03: Injection | Parameterized queries, input validation |
| A04: Insecure Design | Security by design, threat modeling |
| A05: Security Misconfiguration | Secure defaults, configuration validation |
| A06: Vulnerable Components | Regular updates, dependency scanning |
| A07: Authentication Failures | 2FA, rate limiting, account lockout |
| A08: Data Integrity Failures | JWT signatures, CSRF tokens |
| A09: Logging Failures | Comprehensive audit logging |
| A10: SSRF | Input validation, URL whitelisting |

### Security Best Practices
- ✓ Principle of least privilege
- ✓ Defense in depth
- ✓ Secure by default
- ✓ Fail securely
- ✓ Regular security updates
- ✓ Input validation
- ✓ Output encoding
- ✓ Audit logging
- ✓ Error handling
- ✓ Security testing

---

## Security Checklist

### Deployment Security
- [ ] HTTPS enabled with valid certificate
- [ ] Environment variables secured
- [ ] Database credentials rotated
- [ ] JWT secret is strong (256-bit)
- [ ] CORS configured correctly
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] Error messages sanitized
- [ ] Security headers configured
- [ ] Firewall rules configured

### Ongoing Security
- [ ] Regular security updates
- [ ] Dependency vulnerability scanning
- [ ] Audit log review
- [ ] Failed login monitoring
- [ ] Rate limit effectiveness
- [ ] Token expiration review
- [ ] Password policy enforcement
- [ ] 2FA adoption monitoring

---

## Incident Response

### Security Incident Procedure
1. **Detect** - Monitor logs and alerts
2. **Contain** - Lock affected accounts
3. **Investigate** - Review audit logs
4. **Remediate** - Fix vulnerability
5. **Recover** - Restore normal operations
6. **Document** - Record incident details

### Emergency Actions
- **Compromised Account:** Lock account, force password reset
- **Suspicious Activity:** Enable 2FA, review access logs
- **Data Breach:** Notify users, reset all passwords
- **System Compromise:** Take offline, investigate, rebuild

---

## Appendix

### Security Configuration Files

#### .env (Secrets)
```bash
JWT_SECRET=<256-bit-random-key>
DB_PASSWORD=<strong-password>
SECURE_API_SECRET=<api-key>
BCRYPT_SALT_ROUNDS=12
```

#### SMTP Configuration
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<email>
SMTP_PASSWORD=<app-password>
```

### Security Contacts
- **Security Team:** security@secureaccess.com
- **Incident Response:** incident@secureaccess.com
- **Vulnerability Reports:** security@secureaccess.com

---

**Document Version:** 1.0  
**Classification:** Internal Use  
**Last Review:** December 2024  
**Next Review:** March 2025

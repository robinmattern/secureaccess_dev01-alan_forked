# Program Specifications
## SecureAccess (SAS) - Secure Authentication System

**Version:** 1.02  
**Project Number:** 55  
**Last Updated:** December 2024

---

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [API Specifications](#api-specifications)
5. [Database Schema](#database-schema)
6. [Security Features](#security-features)
7. [Error Handling](#error-handling)
8. [Configuration Management](#configuration-management)
9. [Deployment Specifications](#deployment-specifications)

---

## System Overview

### Purpose
SecureAccess is a centralized authentication and authorization system that provides secure user management, multi-factor authentication, and application access control.

### Key Features
- User authentication with JWT tokens
- Two-factor authentication (2FA) via email
- Security questions for password recovery
- Role-based access control (Admin/User)
- Application registration and user-app relationships
- PKCE (Proof Key for Code Exchange) token support
- Session management with HTTP-only cookies

### System Components
- **Client Application** - HTML/JavaScript frontend
- **API Server** - Node.js/Express backend
- **Database** - MySQL
- **Cache Layer** - Redis (optional, with in-memory fallback)

---

## Architecture

### Client-Server Model
```
┌─────────────────┐         ┌─────────────────┐         ┌──────────────┐
│  Client (Web)   │ ◄─────► │   API Server    │ ◄─────► │   Database   │
│  Port: 55101    │  HTTPS  │  Port: 55151    │   SQL   │    MySQL     │
└─────────────────┘         └─────────────────┘         └──────────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │  Redis Cache    │
                            │   (Optional)    │
                            └─────────────────┘
```

### Directory Structure
```
SAS_/
├── client/c01_client-first-app/
│   ├── index.html                 # Login page
│   ├── admin-users.html           # Admin user management
│   ├── profile-page.html          # User profile
│   ├── forgot-password.html       # Password recovery
│   ├── shared-functions.js        # Shared utilities
│   ├── pkce-utils.js              # PKCE implementation
│   └── lib/acm_Prompts.js         # Custom prompts
├── server/s01_server-first-api/
│   ├── server.js                  # Main server file
│   ├── _config.js                 # Configuration
│   ├── controllers/
│   │   ├── authController.js      # Authentication logic
│   │   ├── usersController.js     # User management
│   │   └── applicationsController.js
│   ├── routes/
│   │   ├── users.js
│   │   └── applications.js
│   ├── middleware/
│   │   ├── auth.js                # JWT verification
│   │   └── security.js            # Security utilities
│   ├── utils/
│   │   └── errorHandler.js        # Error handling
│   └── database.js                # DB connection pool
└── docs/_FinalDocuments/
    ├── ExecutiveSummary.md
    └── ProgramSpecs.md
```

---

## Technology Stack

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| Node.js | 14+ | Runtime environment |
| Express.js | 4.x | Web framework |
| MySQL | 8.0+ | Database |
| bcrypt | 5.x | Password hashing |
| jsonwebtoken | 9.x | JWT tokens |
| Joi | 17.x | Input validation |
| speakeasy | 2.x | 2FA TOTP |
| nodemailer | 6.x | Email delivery |
| Redis | 4.x | Cache (optional) |

### Frontend
| Technology | Purpose |
|------------|---------|
| HTML5 | Structure |
| JavaScript (ES6+) | Logic |
| CSS3 | Styling |
| Fetch API | HTTP requests |

### Security
- CSRF protection (double-submit cookie pattern)
- HTTP-only cookies for JWT storage
- bcrypt (12 rounds) for password hashing
- Rate limiting on authentication endpoints
- Account lockout after failed attempts
- Input sanitization and validation

---

## API Specifications

### Base Configuration
- **Base URL (Local):** `http://localhost:55151/api`
- **Base URL (Production):** `https://secureaccess247.com/api`
- **Content-Type:** `application/json`
- **Authentication:** JWT Bearer token or HTTP-only cookie

### Authentication Endpoints

#### POST /api/auth/login
**Description:** Authenticate user and generate JWT token

**Request:**
```json
{
  "username": "string",
  "password": "string",
  "twoFactorCode": "string (optional)"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "user_id": 1,
      "username": "john_doe",
      "email": "john@example.com",
      "role": "User",
      "account_status": "Active"
    },
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "sessionId": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```

**Response (2FA Required):**
```json
{
  "success": false,
  "requiresTwoFactor": true,
  "message": "2FA code sent to your email"
}
```

**Status Codes:**
- `200` - Success
- `400` - Missing credentials
- `401` - Invalid credentials
- `403` - Account disabled
- `423` - Account locked
- `429` - Too many attempts

---

#### POST /api/auth/check-email
**Description:** Check if email exists in system

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "exists": true
}
```

---

#### POST /api/auth/security-questions
**Description:** Retrieve security questions for password reset

**Request:**
```json
{
  "username": "john_doe"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "security_question_1": "What is your favorite color?",
    "security_question_2": "What city were you born in?"
  }
}
```

---

#### POST /api/auth/verify-security-answer
**Description:** Verify security answer for password reset

**Request:**
```json
{
  "username": "john_doe",
  "questionNumber": 1,
  "answer": "blue"
}
```

**Response:**
```json
{
  "success": true
}
```

---

#### POST /api/auth/update-password
**Description:** Update password after security verification

**Request:**
```json
{
  "username": "john_doe",
  "newPassword": "NewSecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password updated successfully"
}
```

---

### User Management Endpoints

#### GET /api/users
**Description:** Get all users (Admin only)

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "user_id": 1,
      "first_name": "John",
      "last_name": "Doe",
      "username": "john_doe",
      "email": "john@example.com",
      "account_status": "Active",
      "role": "User",
      "two_factor_enabled": true,
      "created_at": "2024-01-01T00:00:00.000Z"
    }
  ],
  "count": 1
}
```

---

#### GET /api/users/me
**Description:** Get own profile

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user_id": 1,
    "first_name": "John",
    "last_name": "Doe",
    "username": "john_doe",
    "email": "john@example.com",
    "account_status": "Active",
    "security_question_1": "What is your favorite color?",
    "security_question_2": "What city were you born in?",
    "two_factor_enabled": true,
    "token_expiration_minutes": 60
  }
}
```

---

#### GET /api/users/:id
**Description:** Get user by ID

**Headers:**
```
Authorization: Bearer <token>
```

**Response:** Same as GET /api/users/me

---

#### POST /api/users
**Description:** Create new user

**Headers:**
```
X-Requested-With: XMLHttpRequest
X-CSRF-Token: <csrf_token>
```

**Request:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "security_question_1": "What is your favorite color?",
  "security_answer_1": "blue",
  "security_question_2": "What city were you born in?",
  "security_answer_2": "Boston",
  "two_factor_enabled": false,
  "token_expiration_minutes": 60
}
```

**Response:**
```json
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "user_id": 1,
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

**Status Codes:**
- `201` - Created
- `400` - Validation error
- `409` - Username/email exists

---

#### PUT /api/users/me
**Description:** Update own profile

**Headers:**
```
Authorization: Bearer <token>
X-Requested-With: XMLHttpRequest
X-CSRF-Token: <csrf_token>
```

**Request:**
```json
{
  "first_name": "John",
  "last_name": "Smith",
  "email": "john.smith@example.com",
  "password": "NewPassword123!",
  "security_question_1": "What is your pet's name?",
  "security_answer_1": "Fluffy"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User updated successfully",
  "data": {
    "user_id": 1,
    "first_name": "John",
    "last_name": "Smith",
    "email": "john.smith@example.com"
  }
}
```

---

#### DELETE /api/users/:id
**Description:** Delete user (Admin only)

**Headers:**
```
Authorization: Bearer <token>
X-Requested-With: XMLHttpRequest
X-CSRF-Token: <csrf_token>
```

**Response:**
```json
{
  "success": true,
  "message": "User deleted successfully"
}
```

---

### Application Management Endpoints

#### GET /api/applications
**Description:** Get all applications

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "application_id": 1,
      "application_name": "IODD",
      "description": "Inventory Database",
      "status": "active",
      "created_at": "2024-01-01T00:00:00.000Z"
    }
  ],
  "count": 1
}
```

---

#### GET /api/user-applications
**Description:** Get applications assigned to current user

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "application_id": 1,
      "application_name": "IODD",
      "description": "Inventory Database",
      "redirect_URL": "http://localhost:3000/dashboard"
    }
  ]
}
```

---

## Database Schema

### sa_users Table
```sql
CREATE TABLE sa_users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  master_password_hash VARCHAR(255) NOT NULL,
  salt VARCHAR(64) NOT NULL,
  account_status ENUM('Active', 'Inactive', 'Suspended') DEFAULT 'Active',
  
  -- Security Questions
  security_question_1 TEXT,
  security_answer_1_hash VARCHAR(255),
  security_question_2 TEXT,
  security_answer_2_hash VARCHAR(255),
  
  -- Two-Factor Authentication
  two_factor_enabled BOOLEAN DEFAULT FALSE,
  two_factor_secret VARCHAR(255),
  two_factor_method ENUM('email', 'sms', 'app') DEFAULT 'email',
  two_factor_email VARCHAR(100),
  two_factor_phone VARCHAR(20),
  two_factor_verified BOOLEAN DEFAULT FALSE,
  backup_codes TEXT,
  
  -- JWT Management
  jwt_secret_version INT DEFAULT 1,
  refresh_token_rotation_enabled BOOLEAN DEFAULT TRUE,
  token_expiration_minutes INT DEFAULT 60,
  
  -- Role & Permissions
  role ENUM('User', 'Admin') DEFAULT 'User',
  
  -- Timestamps
  account_creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login_timestamp TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### sa_applications Table
```sql
CREATE TABLE sa_applications (
  application_id INT AUTO_INCREMENT PRIMARY KEY,
  application_name VARCHAR(100) NOT NULL,
  description TEXT,
  redirect_URL VARCHAR(255),
  failure_URL VARCHAR(255),
  app_key VARCHAR(100),
  security_roles VARCHAR(255),
  parm_email ENUM('Yes', 'No') DEFAULT 'No',
  parm_username ENUM('Yes', 'No') DEFAULT 'No',
  parm_PKCE ENUM('Yes', 'No') DEFAULT 'No',
  status ENUM('Active', 'Inactive') DEFAULT 'Inactive',
  date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  date_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### sa_app_user Table
```sql
CREATE TABLE sa_app_user (
  app_user_id INT AUTO_INCREMENT PRIMARY KEY,
  application_id INT NOT NULL,
  user_id INT NOT NULL,
  app_role VARCHAR(50),
  status ENUM('Active', 'Inactive') DEFAULT 'Inactive',
  track_user ENUM('Yes', 'No') DEFAULT 'No',
  start_date DATE,
  end_date DATE,
  FOREIGN KEY (application_id) REFERENCES sa_applications(application_id),
  FOREIGN KEY (user_id) REFERENCES sa_users(user_id),
  UNIQUE KEY unique_app_user (application_id, user_id)
);
```

---

## Security Features

### Password Security
- **Algorithm:** bcrypt with 12 salt rounds
- **Minimum Length:** 8 characters
- **Requirements:** 
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character

### JWT Token Management
- **Algorithm:** HS256
- **Expiration:** 24 hours (configurable)
- **Storage:** HTTP-only cookies
- **Claims:**
  - `user_id` - User identifier
  - `username` - Username
  - `email` - Email address
  - `role` - User role (Admin/User)
  - `account_status` - Account status
  - `iat` - Issued at timestamp
  - `exp` - Expiration timestamp
  - `iss` - Issuer: "SecureAccess"
  - `aud` - Audience: "SecureAccess-Users"

### Two-Factor Authentication
- **Method:** Email-based TOTP
- **Code Length:** 8 digits
- **Expiration:** 10 minutes
- **Storage:** Redis (with in-memory fallback)
- **Rate Limiting:** 5 attempts per 10 minutes
- **Backup Codes:** 10 codes, 8 characters each

### CSRF Protection
- **Method:** Double-submit cookie pattern
- **Header Required:** `X-Requested-With: XMLHttpRequest`
- **Token Header:** `X-CSRF-Token`
- **Cookie:** `_csrf` (httpOnly, sameSite: lax)

### Rate Limiting
| Endpoint | Limit | Window |
|----------|-------|--------|
| Login | 5 attempts | 15 minutes |
| 2FA Verification | 5 attempts | 10 minutes |
| General API | 100 requests | 15 minutes |

### Account Lockout
- **Threshold:** 5 failed login attempts
- **Duration:** 30 minutes
- **Reset:** Automatic after duration or manual by admin

---

## Error Handling

### Centralized Error Handler
**Location:** `server/s01_server-first-api/utils/errorHandler.js`

**Function Signature:**
```javascript
handleError(error, res, context, statusCode = 500, userMessage = null)
```

**Features:**
- Timestamp logging
- Context-aware messages
- Stack trace logging (development only)
- Consistent response format
- Prevents header-already-sent errors

**Error Response Format:**
```json
{
  "success": false,
  "message": "Failed to create user",
  "error": "Detailed error message (development only)"
}
```

### HTTP Status Codes
| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful GET/PUT/PATCH |
| 201 | Created | Successful POST |
| 400 | Bad Request | Validation errors |
| 401 | Unauthorized | Missing/invalid token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Duplicate entry |
| 423 | Locked | Account locked |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server errors |

---

## Configuration Management

### Environment Variables
**File:** `.env`

```bash
# Server Configuration
PORT=55151
HOST=http://localhost
NODE_ENV=development

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=<required>
DB_NAME=secureaccess2
DB_LOCATION=Local

# Security
JWT_SECRET=<required>
BCRYPT_SALT_ROUNDS=12

# API Keys
SECURE_API_SECRET=<required>
IODD_APP_KEY=<required>

# Redis (Optional)
REDIS_ENABLED=false
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# CORS
CORS_ORIGINS=http://localhost:55101,http://localhost:55151
```

### SMTP Configuration
**File:** `.env.SMTP`

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<email>
SMTP_PASSWORD=<app_password>
SMTP_FROM_EMAIL=<email>
```

### Application Configuration
**File:** `server/s01_server-first-api/_config.js`

```javascript
{
  PROJECT_NO: "55",
  PROJECT_NAME: "SAS",
  PROJECT_VERSION: "1.02",
  CLIENT_PORT: "55101",
  CLIENT_HOST: "http://localhost:55101",
  SERVER_PORT: "55151",
  SERVER_API_URL: "http://localhost:55151/api",
  SECURE_API_SECRET: process.env.SECURE_API_SECRET || null,
  IODD_APP_KEY: process.env.IODD_APP_KEY || null,
  CORS_ORIGINS: [
    "http://localhost:55101",
    "http://127.0.0.1:55101",
    "http://localhost:55151",
    "http://127.0.0.1:55151"
  ]
}
```

---

## Deployment Specifications

### System Requirements
- **Node.js:** 14.x or higher
- **MySQL:** 8.0 or higher
- **Redis:** 4.x or higher (optional)
- **Memory:** 512MB minimum, 2GB recommended
- **Storage:** 1GB minimum

### Port Configuration
| Service | Port | Protocol |
|---------|------|----------|
| Client | 55101 | HTTP/HTTPS |
| API Server | 55151 | HTTP/HTTPS |
| MySQL | 3306 | TCP |
| Redis | 6379 | TCP |

### Installation Steps
1. Clone repository
2. Install dependencies: `npm install`
3. Configure `.env` file
4. Configure `.env.SMTP` file
5. Initialize database: `mysql < schema.sql`
6. Start server: `npm start`

### Production Considerations
- Enable HTTPS with valid SSL certificates
- Set `NODE_ENV=production`
- Use process manager (PM2, systemd)
- Enable Redis for production
- Configure firewall rules
- Set up database backups
- Enable application monitoring
- Configure log rotation

### Performance Optimization
- SMTP configuration caching (5-minute TTL)
- Database connection pooling (10 connections)
- Redis caching for 2FA codes
- Rate limiting to prevent abuse
- Gzip compression for responses

---

## Appendix

### Validation Schemas

#### User Creation Schema
```javascript
{
  first_name: Joi.string().max(100).required(),
  last_name: Joi.string().max(100).required(),
  username: Joi.string().max(255).required(),
  email: Joi.string().email().max(255).required(),
  password: Joi.string().min(8).required(),
  security_question_1: Joi.string().optional(),
  security_answer_1: Joi.string().optional(),
  security_question_2: Joi.string().optional(),
  security_answer_2: Joi.string().optional(),
  two_factor_enabled: Joi.boolean().default(false),
  token_expiration_minutes: Joi.number().integer().min(1).max(1440).default(60)
}
```

#### User Update Schema
```javascript
{
  first_name: Joi.string().max(100).optional(),
  last_name: Joi.string().max(100).optional(),
  username: Joi.string().max(255).optional(),
  email: Joi.string().email().max(255).optional(),
  password: Joi.string().min(8).optional(),
  account_status: Joi.string().valid('active', 'inactive', 'locked').optional(),
  security_question_1: Joi.string().optional(),
  security_answer_1: Joi.string().optional(),
  security_question_2: Joi.string().optional(),
  security_answer_2: Joi.string().optional(),
  two_factor_enabled: Joi.boolean().optional(),
  token_expiration_minutes: Joi.number().integer().min(1).max(1440).optional(),
  toggleTwoFactor: Joi.boolean().optional()
}
```

---

**Document Version:** 1.0  
**Last Updated:** December 2024  
**Maintained By:** Development Team

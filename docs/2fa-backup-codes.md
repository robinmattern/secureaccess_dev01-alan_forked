# 2-Factor Authentication with Backup Codes

## Overview
SecureAccess now supports 2-factor authentication with backup codes for account recovery.

## Features

### 2FA Authentication
- **8-digit codes** sent via email
- **10-minute expiration** on codes
- **Rate limiting**: 5 attempts per 10 minutes
- **Redis support**: Optional persistent storage (falls back to in-memory)
- **Audit logging**: All 2FA events tracked

### Backup Codes
- **10 one-time codes** per user
- **8 characters** each (e.g., A3F8C9D2)
- **Hashed storage** (bcrypt) - cannot be reversed
- **Single use** - deleted after use
- **Admin generation** - via 2FA management page

## How to Use

### For Admins

1. **Enable 2FA for User:**
   - Go to Admin → Users → Select User
   - Click "2-Factor Authentication" button
   - Set "2-Factor Enabled" to "Yes"
   - Enter user's email address
   - Click "Save"

2. **Generate Backup Codes:**
   - On 2FA page, click "Backup Codes" button
   - Confirm generation (replaces existing codes)
   - Save the 10 codes shown (only displayed once)
   - Provide codes to user securely

3. **Test 2FA:**
   - Click "Test" button to send test email
   - Verify email delivery

### For Users

1. **Login with 2FA:**
   - Enter username and password
   - System sends 8-digit code to email
   - Enter code in "2-Factor Code" field
   - Click "Login"

2. **Use Backup Code:**
   - If email not accessible, enter backup code instead
   - Backup code works same as email code
   - Each code can only be used once
   - Remaining codes still valid

## Configuration

### Enable Redis (Optional)
In `.env` file:
```env
REDIS_ENABLED=true
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
```

### SMTP Configuration
In `.env.SMTP` file:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## Security Features

✅ **8-digit codes** (100 million combinations)
✅ **Rate limiting** (5 attempts per 10 minutes)
✅ **Auto-expiration** (10 minutes)
✅ **Hashed storage** (bcrypt)
✅ **One-time use** (codes deleted after use)
✅ **Audit logging** (all events tracked)
✅ **Redis support** (survives server restarts)

## Audit Events

- `2FA_CODE_SENT` - Code generated and emailed
- `2FA_EMAIL_FAILED` - Email sending failed
- `2FA_CODE_EXPIRED` - Expired code used
- `2FA_CODE_INVALID` - Wrong code entered
- `2FA_SUCCESS` - Code verified successfully
- `2FA_RATE_LIMIT` - Too many attempts
- `BACKUP_CODES_GENERATED` - Admin generated codes
- `2FA_BACKUP_CODE_USED` - User used backup code

## Database Schema

```sql
ALTER TABLE sa_users ADD COLUMN backup_codes TEXT AFTER two_factor_verified;
```

Stores JSON array of hashed backup codes:
```json
["$2b$12$hash1...", "$2b$12$hash2...", ...]
```

## Best Practices

1. **Generate backup codes** when enabling 2FA
2. **Store codes securely** (password manager, encrypted file)
3. **Monitor audit logs** for suspicious activity
4. **Regenerate codes** if compromised
5. **Use Redis** in production for reliability
6. **Test SMTP** before enabling 2FA for users

## Troubleshooting

**Email not received:**
- Check SMTP configuration in admin-smtp.html
- Use "Test" button to verify email delivery
- Check spam/junk folder

**Backup codes not working:**
- Verify codes were generated (check audit log)
- Ensure codes haven't been used already
- Each code works only once

**Redis connection failed:**
- System automatically falls back to in-memory storage
- Check Redis server is running: `redis-cli ping`
- Verify REDIS_HOST and REDIS_PORT in .env

## API Endpoints

- `POST /api/auth/login` - Login with 2FA support
- `POST /api/users/:id/backup-codes` - Generate backup codes (admin only)
- `POST /api/test-2fa` - Test email delivery (admin only)

# Email Verification Bypass Vulnerabilities

> [!WARNING]
> **HIGH SEVERITY VULNERABILITIES** - Based on HackerOne reports and Medium security research. For educational purposes only.

## Overview

Implemented **4 email verification bypass techniques** based on bug bounty reports and security research. These demonstrate how attackers can bypass email verification to gain unauthorized access or manipulate user accounts.

---

## Vulnerabilities

### 1. Email Verification API Endpoint Bypass

**Severity**: Critical  
**Source**: Medium Bug Bounty Reports

**Vulnerability**: Direct API endpoint access allows account activation without email verification token.

**Exploitation**:
```bash
# 1. Register account
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"password123","name":"Attacker"}'

# 2. Directly call activation endpoint (no token required!)
curl -X POST http://localhost:3000/api/additional-auth/activate-account-direct \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com"}'
# Account activated without email verification!

# 3. Login with unverified email
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"password123"}'
```

**Impact**: Account creation without email ownership proof, spam accounts, abuse.

**Secure Implementation**:
```typescript
export const activateAccountSecure = async (req: Request, res: Response) => {
    const { email, verificationToken } = req.body;
    
    // Require verification token
    if (!verificationToken) {
        return res.status(400).json({ message: 'Verification token required' });
    }
    
    // Validate token
    const storedToken = emailVerificationTokens[email];
    if (storedToken !== verificationToken) {
        return res.status(400).json({ message: 'Invalid verification token' });
    }
    
    // Activate account
    await prisma.user.update({
        where: { email },
        data: { emailVerified: true }
    });
    
    // Invalidate token
    delete emailVerificationTokens[email];
};
```

---

### 2. Email Change Without Re-verification

**Severity**: High  
**Source**: HackerOne Reports

**Vulnerability**: Users can change their email address without verifying ownership of the new email.

**Exploitation**:
```bash
# 1. Attacker creates account with attacker@test.com
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"password123","name":"Attacker"}'

# 2. Verify attacker@test.com
# (normal verification flow)

# 3. Change email to victim@test.com WITHOUT verification
curl -X POST http://localhost:3000/api/additional-auth/change-email-no-verification \
  -H "Content-Type: application/json" \
  -d '{"currentEmail":"attacker@test.com","newEmail":"victim@test.com"}'
# Email changed without verifying victim@test.com!

# 4. Account now has victim's email but attacker controls it
# Can be used for password reset, notifications, etc.
```

**Impact**: Email takeover, account confusion, phishing attacks.

**Secure Implementation**:
```typescript
export const changeEmailSecure = async (req: Request, res: Response) => {
    const { newEmail } = req.body;
    const userId = req.userId;
    
    // Generate verification token for NEW email
    const verificationToken = crypto.randomBytes(32).toString('hex');
    pendingEmailChanges[verificationToken] = {
        userId,
        newEmail,
        expires: Date.now() + 15 * 60 * 1000
    };
    
    // Send verification email to NEW address
    await sendVerificationEmail(newEmail, verificationToken);
    
    res.json({
        message: 'Verification email sent to new address',
        requiresVerification: true
    });
};
```

---

### 3. Email Verification Race Condition

**Severity**: High  
**Source**: HackerOne #2024 Email Verification Bypass

**Vulnerability**: Race condition allows same OTP to verify both attacker and victim email addresses.

**Exploitation**:
```bash
# 1. Attacker initiates email change to victim@test.com
curl -X POST http://localhost:3000/api/additional-auth/request-email-change \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","newEmail":"victim@test.com"}'
# OTP sent to victim@test.com

# 2. Simultaneously send verification requests
# Request 1: Verify victim@test.com with OTP
# Request 2: Verify attacker@test.com with same OTP

curl -X POST http://localhost:3000/api/additional-auth/verify-email-change \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","otp":"123456"}' &

curl -X POST http://localhost:3000/api/additional-auth/verify-email-change \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","otp":"123456"}' &

# Race condition: both emails verified with same OTP!
```

**Impact**: Email verification bypass, account takeover.

**Secure Implementation**:
```typescript
const verificationLocks: { [email: string]: boolean } = {};

export const verifyEmailChangeSecure = async (req: Request, res: Response) => {
    const { email, otp } = req.body;
    
    // Acquire lock for this email
    if (verificationLocks[email]) {
        return res.status(429).json({ message: 'Verification in progress' });
    }
    
    verificationLocks[email] = true;
    
    try {
        // Verify OTP
        if (emailVerificationTokens[email] === otp) {
            // Mark as verified
            await prisma.user.update({
                where: { email },
                data: { emailVerified: true }
            });
            
            // Invalidate OTP immediately
            delete emailVerificationTokens[email];
            
            res.json({ message: 'Email verified' });
        } else {
            res.status(400).json({ message: 'Invalid OTP' });
        }
    } finally {
        // Release lock
        delete verificationLocks[email];
    }
};
```

---

### 4. Front-end Only Email Verification

**Severity**: High  
**Source**: Medium Security Research

**Vulnerability**: Email verification enforced client-side only, not validated server-side.

**Exploitation**:
```bash
# 1. Register account
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"password123","name":"Attacker"}'

# 2. Login (client shows "verify email" message)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"password123"}'
# Returns JWT token

# 3. Directly access protected endpoints (server doesn't check!)
curl -X GET http://localhost:3000/api/additional-auth/access-without-email-verification \
  -H "Authorization: Bearer <token>"
# Works! Server doesn't enforce email verification
```

**Impact**: Unverified accounts accessing protected features, spam, abuse.

**Secure Implementation**:
```typescript
// Middleware to check email verification
export const requireEmailVerification = async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.userId;
    
    const user = await prisma.user.findUnique({ where: { id: userId } });
    
    // Server-side check
    if (!user.emailVerified) {
        return res.status(403).json({
            message: 'Email verification required',
            requiresVerification: true
        });
    }
    
    next();
};

// Apply to protected routes
router.get('/protected', authenticateToken, requireEmailVerification, handler);
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/additional-auth/activate-account-direct` | POST | Direct API bypass |
| `/api/additional-auth/change-email-no-verification` | POST | Email change without verification |
| `/api/additional-auth/request-email-change` | POST | Email verification race condition |
| `/api/additional-auth/verify-email-change` | POST | Verify email change |
| `/api/additional-auth/access-without-email-verification` | GET | Front-end only verification |

---

## Testing Checklist

- [ ] Test direct activation without token
- [ ] Test email change without verification
- [ ] Test email verification race condition
- [ ] Test accessing resources without email verification

---

## Secure Implementation Best Practices

1. **Email Verification Tokens**
   - Always require verification tokens
   - Use cryptographically secure random tokens
   - Implement expiration (15-30 minutes)
   - One-time use only

2. **Email Changes**
   - Require verification of NEW email address
   - Send notification to OLD email address
   - Implement confirmation period before change
   - Allow cancellation from old email

3. **Race Condition Prevention**
   - Implement proper locking mechanisms
   - Use database transactions
   - Validate state before and after operations
   - Invalidate tokens immediately after use

4. **Server-Side Enforcement**
   - Never trust client-side validation
   - Check email verification status on every protected request
   - Use middleware for consistent enforcement
   - Return appropriate error codes (403 Forbidden)

5. **Token Management**
   - Store tokens securely (hashed)
   - Associate tokens with specific actions
   - Implement rate limiting on verification attempts
   - Log verification attempts for monitoring

---

## References

- [OWASP Email Verification Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [HackerOne Email Verification Reports](https://hackerone.com/reports?q=email+verification)
- [Medium: Email Verification Bypass Techniques](https://medium.com/tag/email-verification)

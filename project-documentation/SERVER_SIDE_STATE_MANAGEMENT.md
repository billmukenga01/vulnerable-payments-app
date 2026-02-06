# Server-Side State Management

## What is Server-Side State?

**Server-side state** refers to data that is stored and managed on the server (backend) rather than on the client (browser). This is critical for security because:

1. **Client-side data can be manipulated** - Users can modify cookies, localStorage, and any data in the browser
2. **Server-side data is trusted** - Only the server can modify this data
3. **Centralized control** - The server is the single source of truth

---

## Types of State Storage

### 1. **In-Memory Storage** (This Application)
Data stored in server RAM using JavaScript objects/variables.

**Pros:**
- ✅ Fast access
- ✅ Simple implementation
- ✅ No database overhead

**Cons:**
- ❌ Lost on server restart
- ❌ Not shared across multiple server instances
- ❌ Limited by RAM

### 2. **Database Storage**
Data stored in persistent databases (PostgreSQL, MongoDB, etc.)

**Pros:**
- ✅ Persistent across restarts
- ✅ Shared across server instances
- ✅ Scalable

**Cons:**
- ❌ Slower than memory
- ❌ More complex

### 3. **Redis/Cache Storage**
In-memory data store with persistence options

**Pros:**
- ✅ Fast like in-memory
- ✅ Can persist to disk
- ✅ Shared across instances

---

## How This Application Manages Server-Side State

### Location: `server/src/controllers/additional-auth.controller.ts`

The application uses **in-memory JavaScript objects** to store server-side state:

```typescript
// In-memory stores (lines 10-19)
const sessions: { [sessionId: string]: any } = {};
const deactivatedAccounts: { [userId: string]: boolean } = {};
const usedOTPs: Set<string> = new Set();
const twoFAResetRequests: { [email: string]: string[] } = {};
const otpAttemptsBySession: { [sessionId: string]: number } = {};
const emailVerificationTokens: { [email: string]: string } = {};
const passwordResetTokens: { [email: string]: string[] } = {};
const rateLimitByIP: { [ip: string]: number } = {};
const rateLimitByUserAgent: { [ua: string]: number } = {};
```

---

## State Categories in This Application

### 1. **Session Management**

**Purpose:** Track authenticated users

```typescript
const sessions: { [sessionId: string]: any } = {};
```

**Example Usage:**
```typescript
// Create session (line 124-125)
const sessionId = `SESSION-${Date.now()}`;
sessions[sessionId] = { userId: user.id, authenticated: true };

// Check session (line 176-178)
if (!sessionId || !sessions[sessionId]) {
    return res.status(401).json({ message: 'Not authenticated' });
}
```

**How it works:**
1. User logs in → Server creates session ID
2. Server stores `{ userId, authenticated: true }` in `sessions` object
3. Session ID sent to client as cookie
4. Client sends session ID with each request
5. Server looks up session ID to verify authentication

---

### 2. **Account State Tracking**

**Purpose:** Track account status (deactivated, etc.)

```typescript
const deactivatedAccounts: { [userId: string]: boolean } = {};
```

**Example Usage:**
```typescript
// Deactivate account (line 39)
deactivatedAccounts[user.id] = true;

// Check if deactivated (line 61)
if (deactivatedAccounts[user.id]) {
    // Bypass 2FA for deactivated accounts (VULNERABILITY!)
}
```

**Vulnerability Demonstrated:**
- Account deactivation state stored server-side
- BUT: Login logic checks this state to bypass 2FA
- **Secure approach:** Deactivated accounts shouldn't be able to login at all

---

### 3. **OTP/2FA State**

**Purpose:** Track OTP usage and attempts

```typescript
const usedOTPs: Set<string> = new Set();
const otpAttemptsBySession: { [sessionId: string]: number } = {};
```

**Example - Reusable OTP Vulnerability (lines 83-107):**
```typescript
export const verifyOTPReusable = async (req: Request, res: Response) => {
    const { email, otp } = req.body;
    
    // Check OTP is correct
    if (user.otp !== otp) {
        return res.status(400).json({ message: 'Invalid OTP' });
    }
    
    // VULNERABILITY: Don't mark OTP as used
    // Should do: usedOTPs.add(otp);
    
    // Issue token without invalidating OTP
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.json({ token });
};
```

**Secure Implementation:**
```typescript
// Check if OTP already used
if (usedOTPs.has(otp)) {
    return res.status(400).json({ message: 'OTP already used' });
}

// Verify OTP
if (user.otp !== otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
}

// Mark as used (SERVER-SIDE STATE!)
usedOTPs.add(otp);

// Issue token
const token = jwt.sign({ userId: user.id }, JWT_SECRET);
```

---

### 4. **Rate Limiting State**

**Purpose:** Track request attempts to prevent brute force

```typescript
const rateLimitByIP: { [ip: string]: number } = {};
const rateLimitByUserAgent: { [ua: string]: number } = {};
const otpAttemptsBySession: { [sessionId: string]: number } = {};
```

**Example - Session-Based Rate Limiting (lines 335-366):**
```typescript
export const verifyOTPWithSessionRateLimit = async (req: Request, res: Response) => {
    const sessionId = req.cookies.sessionId || 'default';
    
    // VULNERABILITY: Rate limit tied to session ID
    if (otpAttemptsBySession[sessionId] >= 5) {
        return res.status(429).json({ message: 'Too many attempts' });
    }
    
    // Increment attempts (SERVER-SIDE STATE)
    otpAttemptsBySession[sessionId] = (otpAttemptsBySession[sessionId] || 0) + 1;
    
    // Verify OTP...
};
```

**Vulnerability:**
- Rate limit stored server-side ✅
- BUT: Tied to session ID which client controls ❌
- **Exploit:** Request new session ID → Reset rate limit counter

**Secure Implementation:**
```typescript
// Rate limit by user ID + IP address (both server-side)
const key = `${userId}-${req.ip}`;
if (rateLimitByUserIP[key] >= 5) {
    return res.status(429).json({ message: 'Too many attempts' });
}
```

---

### 5. **Token Management**

**Purpose:** Track password reset tokens, email verification tokens

```typescript
const emailVerificationTokens: { [email: string]: string } = {};
const passwordResetTokens: { [email: string]: string[] } = {};
const twoFAResetRequests: { [email: string]: string[] } = {};
```

**Example - Multiple Valid Tokens (lines 508-535):**
```typescript
export const requestPasswordResetMultiple = async (req: Request, res: Response) => {
    const { email } = req.body;
    
    const token = crypto.randomBytes(32).toString('hex');
    
    // VULNERABILITY: Don't invalidate old tokens
    if (!passwordResetTokens[email]) {
        passwordResetTokens[email] = [];
    }
    passwordResetTokens[email].push(token); // Add to array, keep old ones
    
    res.json({
        token,
        activeTokens: passwordResetTokens[email].length
    });
};
```

**Secure Implementation:**
```typescript
// Replace old tokens instead of appending
passwordResetTokens[email] = [token]; // Only one valid token

// Or invalidate all old tokens
delete passwordResetTokens[email];
passwordResetTokens[email] = [token];
```

---

## Client-Side vs Server-Side State: Critical Differences

### ❌ **Client-Side State (INSECURE)**

**Example - MFA Cookie Vulnerability (lines 145-196):**

```typescript
// Login sets MFA requirement in CLIENT-SIDE cookie
res.cookie('mfa_required', 'true'); // ❌ Client can delete this!
res.cookie('sessionId', sessionId, { httpOnly: true });

// Access check trusts CLIENT-SIDE cookie
export const accessWithoutMFA = async (req: Request, res: Response) => {
    const mfaRequired = req.cookies.mfa_required; // ❌ Reading client data
    
    // VULNERABILITY: Trust client-side cookie
    if (mfaRequired === 'true') {
        return res.status(403).json({ message: 'MFA required' });
    }
    
    // Grant access (MFA bypassed!)
};
```

**Exploit:**
1. Login → Get cookies: `sessionId=ABC`, `mfa_required=true`
2. Delete `mfa_required` cookie in browser
3. Keep `sessionId` cookie
4. Access protected resource → **MFA bypassed!**

---

### ✅ **Server-Side State (SECURE)**

**Secure Implementation:**

```typescript
// Store MFA state SERVER-SIDE
const sessions: { [sessionId: string]: any } = {};

// Login sets MFA requirement in SERVER
sessions[sessionId] = { 
    userId: user.id, 
    mfaRequired: true,  // ✅ Server-side only!
    mfaCompleted: false 
};

// Access check uses SERVER-SIDE state
export const accessWithMFA = async (req: Request, res: Response) => {
    const sessionId = req.cookies.sessionId;
    const session = sessions[sessionId]; // ✅ Read server data
    
    // Check SERVER-SIDE state
    if (session.mfaRequired && !session.mfaCompleted) {
        return res.status(403).json({ message: 'MFA required' });
    }
    
    // Grant access
};

// Complete MFA updates SERVER-SIDE state
export const completeMFA = async (req: Request, res: Response) => {
    const sessionId = req.cookies.sessionId;
    
    // Verify OTP...
    
    // Update SERVER-SIDE state
    sessions[sessionId].mfaCompleted = true; // ✅ Client can't modify this!
};
```

**Why it's secure:**
1. Client only has session ID (random string)
2. MFA state stored on server
3. Client **cannot** modify server memory
4. Server is single source of truth

---

## Common Vulnerabilities in Server-Side State

### 1. **Trusting Client-Controlled Keys**

**Vulnerable:**
```typescript
// Rate limit by session ID (client controls this!)
const sessionId = req.cookies.sessionId;
if (rateLimitBySession[sessionId] >= 5) {
    return res.status(429).json({ message: 'Rate limited' });
}
```

**Exploit:** Get new session ID → Bypass rate limit

**Secure:**
```typescript
// Rate limit by user ID + IP (server controls both)
const key = `${userId}-${req.ip}`;
if (rateLimitByUser[key] >= 5) {
    return res.status(429).json({ message: 'Rate limited' });
}
```

---

### 2. **Not Invalidating State**

**Vulnerable:**
```typescript
// Don't mark OTP as used
if (user.otp === otp) {
    // Issue token without invalidating OTP
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
}
```

**Exploit:** Reuse same OTP multiple times

**Secure:**
```typescript
// Check if already used
if (usedOTPs.has(otp)) {
    return res.status(400).json({ message: 'OTP already used' });
}

// Verify and mark as used
if (user.otp === otp) {
    usedOTPs.add(otp); // ✅ Invalidate server-side
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
}
```

---

### 3. **Race Conditions**

**Vulnerable:**
```typescript
// No synchronization
export const verifyEmailChange = async (req: Request, res: Response) => {
    if (emailVerificationTokens[email] === otp) {
        delete emailVerificationTokens[email]; // ❌ Race condition!
        res.json({ message: 'Verified' });
    }
};
```

**Exploit:** Send 2 concurrent requests → Both succeed

**Secure:**
```typescript
// Atomic check-and-delete
export const verifyEmailChange = async (req: Request, res: Response) => {
    const storedOTP = emailVerificationTokens[email];
    
    if (!storedOTP) {
        return res.status(400).json({ message: 'No pending verification' });
    }
    
    if (storedOTP !== otp) {
        return res.status(400).json({ message: 'Invalid OTP' });
    }
    
    // Delete BEFORE responding
    delete emailVerificationTokens[email];
    
    // Use database transaction for production
    await prisma.$transaction(async (tx) => {
        // Verify and update in single transaction
    });
    
    res.json({ message: 'Verified' });
};
```

---

## Best Practices for Server-Side State

### 1. **Never Trust Client Data for Security Decisions**

❌ **Bad:**
```typescript
const isAdmin = req.cookies.isAdmin; // Client can set this!
if (isAdmin === 'true') {
    // Grant admin access
}
```

✅ **Good:**
```typescript
const userId = req.userId; // From verified JWT
const user = await prisma.user.findUnique({ where: { id: userId } });
if (user.role === 'admin') { // Server-side database check
    // Grant admin access
}
```

---

### 2. **Store Security State Server-Side**

✅ **What to store server-side:**
- Authentication status
- MFA completion status
- Permission levels
- Rate limit counters
- Used tokens/OTPs
- Session data

❌ **Never store client-side:**
- `isAuthenticated` cookie
- `mfaCompleted` cookie
- `role=admin` cookie

---

### 3. **Invalidate State Properly**

✅ **Always invalidate:**
- OTPs after use
- Old reset tokens when new ones generated
- Sessions on logout
- Tokens after password change

---

### 4. **Use Atomic Operations**

For production, use database transactions:

```typescript
// Atomic OTP verification
await prisma.$transaction(async (tx) => {
    const user = await tx.user.findUnique({ where: { email } });
    
    if (user.otp !== otp) {
        throw new Error('Invalid OTP');
    }
    
    // Mark as used in same transaction
    await tx.user.update({
        where: { id: user.id },
        data: { otp: null, otpUsedAt: new Date() }
    });
});
```

---

## Summary

**Server-Side State** = Data stored on the server that clients cannot modify

**This Application Uses:**
- In-memory JavaScript objects
- 9 different state stores for different purposes
- Demonstrates both vulnerable and secure patterns

**Key Principle:**
> **Never trust the client for security decisions. Always verify and store security-critical state on the server.**

**Remember:**
- Client data (cookies, localStorage) = **Untrusted**
- Server data (memory, database) = **Trusted**
- Security decisions = **Always use server-side state**

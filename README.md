# Vulnerable Payments App

> [!WARNING]
> **This application contains intentional security vulnerabilities for educational purposes.**  
> **DO NOT deploy to production or use with real data!**

A full-stack payment application built with React, TypeScript, Express, and Prisma, intentionally designed with security vulnerabilities for learning and penetration testing practice.

## 🎯 Purpose

This project demonstrates common web application vulnerabilities found in real-world bug bounty reports from HackerOne, OWASP, and security research. It's designed for:
- Security training and education
- Penetration testing practice
- Understanding common authentication flaws
- Learning secure coding practices by example

## 📊 Vulnerability Summary

**Total Vulnerabilities Implemented: 61**

- Authentication & Authorization: 57 vulnerabilities
- Infrastructure Security: 6 vulnerabilities
- CORS Misconfigurations: 3 vulnerabilities

All vulnerabilities are based on real HackerOne reports, OWASP guidelines, and security research from 2023-2024.

## 🔓 Implemented Vulnerabilities

### Authentication & Authorization
- **OTP/2FA Bypass** (7 vulnerabilities)
  - OTP disclosure in API responses
  - Weak 4-digit OTP generation
  - No rate limiting
  - OTP reuse allowed
  - Infinite OTP validity
  - User enumeration
  - Response timing attacks

- **OAuth Vulnerabilities** (7 vulnerabilities)
  - Missing state parameter validation (CSRF)
  - Insufficient redirect URI validation
  - Pre-account takeover
  - Account linking race conditions
  - Token leakage via URL parameters
  - No email verification
  - Weak state generation

- **Business Logic Flaws** (12 vulnerabilities)
  - Response manipulation bypass
  - Direct endpoint access without 2FA
  - Remember device bypass (forgeable cookies)
  - Weak password reset tokens
  - No token invalidation
  - Multiple active reset tokens
  - Race conditions
  - Host header injection

- **JWT Vulnerabilities** (5 vulnerabilities) 🆕
  - None algorithm bypass
  - Weak JWT secret (brute-forceable)
  - Algorithm confusion (RS256 → HS256)
  - kid SQL injection
  - kid path traversal

- **Session Management** (4 vulnerabilities) 🆕
  - Session fixation
  - Predictable session IDs
  - No session invalidation on logout
  - No session invalidation on password change

- **Advanced 2FA Bypasses** (3 vulnerabilities)
  - Blank/null OTP bypass
  - OAuth login bypasses 2FA
  - Session persistence after 2FA activation

- **Additional Auth Bypasses** (3 vulnerabilities)
  - Password reset poisoning (host header injection)
  - Account lockout bypass via case sensitivity
  - Credential stuffing (no global rate limiting)

- **Advanced OTP/2FA Bypasses** (8 vulnerabilities) 🆕
  - Account deactivation → password reset bypass
  - Reusable OTP (no invalidation after use)
  - Email OTP bypass via early session cookie
  - 2FA bypass via cookie deletion
  - Expired TOTP code acceptance
  - Bypassing phone number OTP in account recovery
  - 2FA race condition (multiple reset requests)
  - OTP brute force via session ID rotation

- **Email Verification Bypasses** (4 vulnerabilities) 🆕
  - Email verification API endpoint bypass
  - Email change without re-verification
  - Email verification race condition
  - Front-end only email verification

- **Password Reset Flaws** (4 vulnerabilities) 🆕
  - Multiple valid reset tokens
  - Password reset race condition
  - 0-click account takeover via reset flaw
  - Password reset token in URL (Referer leakage)

- **Rate Limiting Bypasses** (4 vulnerabilities) 🆕
  - Rate limit bypass via X-Forwarded-For
  - Rate limit bypass via User-Agent rotation
  - Rate limit bypass via parameter pollution
  - Rate limit bypass via HTTP method switching

### Infrastructure
- **Container Security Issues**
  - Containers run as root
  - Full Linux capabilities enabled
  - Writable root filesystem
  - Permissive seccomp profile

- **CORS Misconfigurations**
  - Accepts null origin
  - Weak regex validation
  - Credentials enabled with weak checks

## 📚 Documentation

All vulnerabilities are thoroughly documented in the `project-documentation/` folder:

### Authentication Vulnerabilities
- **[OTP_VULNERABILITIES.md](project-documentation/OTP_VULNERABILITIES.md)** - OTP/2FA bypass techniques
- **[OAUTH_VULNERABILITIES.md](project-documentation/OAUTH_VULNERABILITIES.md)** - OAuth authentication flaws
- **[AUTH_BUSINESS_LOGIC_FLAWS.md](project-documentation/AUTH_BUSINESS_LOGIC_FLAWS.md)** - Authentication business logic issues
- **[JWT_VULNERABILITIES.md](project-documentation/JWT_VULNERABILITIES.md)** - JWT security flaws
- **[SESSION_VULNERABILITIES.md](project-documentation/SESSION_VULNERABILITIES.md)** - Session management issues
- **[ADVANCED_2FA_BYPASSES.md](project-documentation/ADVANCED_2FA_BYPASSES.md)** - Advanced 2FA bypass techniques
- **[AUTHENTICATION_BYPASSES.md](project-documentation/AUTHENTICATION_BYPASSES.md)** - Additional auth bypass methods
- **[ADVANCED_OTP_BYPASSES.md](project-documentation/ADVANCED_OTP_BYPASSES.md)** - Advanced OTP/2FA bypasses (8 vulnerabilities) 🆕
- **[EMAIL_VERIFICATION_BYPASSES.md](project-documentation/EMAIL_VERIFICATION_BYPASSES.md)** - Email verification bypass techniques (4 vulnerabilities) 🆕
- **[PASSWORD_RESET_FLAWS.md](project-documentation/PASSWORD_RESET_FLAWS.md)** - Password reset vulnerabilities (4 vulnerabilities) 🆕
- **[RATE_LIMITING_BYPASSES.md](project-documentation/RATE_LIMITING_BYPASSES.md)** - Rate limiting bypass techniques (4 vulnerabilities) 🆕

### Infrastructure & Concepts
- **[TUNNEL_EXPLANATION.md](project-documentation/TUNNEL_EXPLANATION.md)** - How Cloudflare tunnels work
- **[security_concepts.md](project-documentation/security_concepts.md)** - Security concepts overview

Each document includes:
- Detailed vulnerability descriptions
- Exploitation techniques with code examples
- Impact assessments
- Secure implementation guidelines
- References to real HackerOne reports

## 🚀 Quick Start

### Prerequisites
- Node.js v20+
- npm
- Docker & Docker Compose (for containerized deployment)

### Option 1: Docker Deployment (Recommended)

```bash
# Start Cloudflare tunnels (provides public URLs)
./start_tunnels.sh

# Build and deploy containers
./deploy.sh all

# Access the app via the tunnel URLs shown in the output
```

### Option 2: Local Development

**Server:**
```bash
cd server
npm install
npx prisma migrate dev --name init
npm run dev
```

**Client:**
```bash
cd client
npm install
npm run dev
```

## 🧪 Testing Vulnerabilities

### OTP Bypass
1. Login with email/password
2. Observe OTP displayed in UI (vulnerability showcase)
3. Try brute-forcing with unlimited attempts
4. Reuse the same OTP multiple times

### OAuth Exploits
1. Click "Login with Google" or "Login with GitHub"
2. Complete mock OAuth flow
3. Observe vulnerabilities in action
4. Test pre-account takeover by registering first

### Business Logic Flaws
```bash
# Test response manipulation
curl -X POST http://localhost:3000/api/auth/verify-otp-bypass \
  -d '{"email":"user@test.com","otp":"0000"}'

# Test weak reset tokens
curl -X POST http://localhost:3000/api/auth/forgot-password-v2 \
  -d '{"email":"user@test.com"}'
```

See individual documentation files for detailed exploitation guides.

## 🏗️ Architecture

```
├── server/          # Express backend with Prisma ORM
│   ├── src/
│   │   ├── controllers/    # Business logic (with vulnerabilities)
│   │   ├── routes/         # API endpoints
│   │   ├── middleware/     # Auth & validation
│   │   └── index.ts        # Server entry point
│   └── prisma/
│       └── schema.prisma   # Database schema
│
├── client/          # React frontend with TypeScript
│   └── src/
│       ├── pages/          # Page components
│       ├── components/     # Reusable UI components
│       └── lib/            # API client
│
├── project-documentation/  # Vulnerability documentation
├── deploy.sh               # Docker deployment script
└── start_tunnels.sh        # Cloudflare tunnel setup
```

## 🔒 Security Notes

**This application is intentionally vulnerable!**

- All vulnerabilities are clearly marked with comments in the code
- Each vulnerability includes references to the security principle it violates
- The UI displays active vulnerabilities to users
- Comprehensive documentation explains how to exploit each flaw

**Never use this code in production or with real user data.**

## 📖 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [HackerOne Disclosed Reports](https://hackerone.com/hacktivity)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## 🤝 Contributing

This is an educational project. If you find additional vulnerabilities to add or improvements to the documentation, contributions are welcome!

## ⚖️ License

This project is for educational purposes only. Use responsibly and ethically.

---

**Remember: With great power comes great responsibility. Use this knowledge to build more secure applications, not to harm others.**

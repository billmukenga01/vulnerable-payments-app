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

- **[OTP_VULNERABILITIES.md](project-documentation/OTP_VULNERABILITIES.md)** - OTP/2FA bypass techniques
- **[OAUTH_VULNERABILITIES.md](project-documentation/OAUTH_VULNERABILITIES.md)** - OAuth authentication flaws
- **[AUTH_BUSINESS_LOGIC_FLAWS.md](project-documentation/AUTH_BUSINESS_LOGIC_FLAWS.md)** - Authentication business logic issues
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

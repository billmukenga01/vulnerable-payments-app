# Security Concepts: Vulnerable vs. Secure

This guide demonstrates common security vulnerabilities (OWASP Top 10) and how your current application architecture protects against them.

## 1. SQL Injection (Injection)

**The Vulnerability:**
Attackers insert malicious SQL statements into entry fields for execution (e.g., to dump the database contents to the attacker).

### ❌ Vulnerable Pattern (Raw SQL)
If you were using raw SQL and concatenating strings:

```typescript
// DANGEROUS: Do not do this
const email = req.body.email;
const query = `SELECT * FROM users WHERE email = '${email}'`;
// If email is "admin@example.com' OR '1'='1", the query becomes:
// SELECT * FROM users WHERE email = 'admin@example.com' OR '1'='1'
// This returns ALL users.
```

### ✅ Your Secure Implementation (Prisma ORM)
Prisma uses parameterized queries under the hood. It treats inputs as literal values, not executable code.

```typescript
// YOUR CODE (transaction.controller.ts)
const receiver = await prisma.user.findUnique({ 
    where: { email: receiverEmail } 
});
```
Even if `receiverEmail` is `' OR '1'='1`, Prisma looks for a user with that exact weird email string. It does not execute the SQL command.

---

## 2. Broken Object Level Authorization (BOLA / IDOR)

**The Vulnerability:**
Attackers manipulate IDs (e.g., in the URL or body) to access data belonging to other users.

### ❌ Vulnerable Pattern (Trusting Input)
Relying on the user to tell you who they are via the request body.

```typescript
// DANGEROUS: Trusting user input for identity
export const sendMoney = async (req, res) => {
    const { senderId, amount } = req.body; // Attacker can send ANY senderId
    
    await prisma.user.update({
        where: { id: senderId }, // Attacker moves money from someone else's account
        data: { balance: { decrement: amount } }
    });
}
```

### ✅ Your Secure Implementation (Token Identity)
You derive the identity from the verified JWT token, which the user cannot tamper with (without the secret key).

```typescript
// YOUR CODE (transaction.controller.ts)
export const sendMoney = async (req: Request, res: Response) => {
    // @ts-ignore
    const senderId = req.userId; // Set by auth middleware from the token
    
    // ... logic uses senderId ...
}
```

---

## 3. Mass Assignment

**The Vulnerability:**
Attackers send extra fields in the request that the server didn't expect, but automatically saves to the database (e.g., setting themselves as admin).

### ❌ Vulnerable Pattern (Blind Object Spread)
Passing the entire request body to the database.

```typescript
// DANGEROUS: Updates whatever fields are in req.body
export const updateUser = async (req, res) => {
    await prisma.user.update({
        where: { id: req.userId },
        data: req.body // Attacker sends { "balance": 1000000, "role": "ADMIN" }
    });
}
```

### ✅ Your Secure Implementation (Zod Validation)
You explicitly define what fields are allowed using Zod schemas.

```typescript
// YOUR CODE (transaction.controller.ts)
const sendMoneySchema = z.object({
    receiverEmail: z.string().email(),
    amount: z.number().positive(),
});

// Only extracts 'receiverEmail' and 'amount'. Everything else is ignored.
const { receiverEmail, amount } = sendMoneySchema.parse(req.body);
```

---

## 4. Broken Authentication

**The Vulnerability:**
Allowing unauthenticated users to access protected resources or using weak verification.

### ❌ Vulnerable Pattern (No Middleware)
Forgetting to protect the route.

```typescript
// DANGEROUS: No check if user is logged in
router.post('/send', transactionController.sendMoney);
```

### ✅ Your Secure Implementation (JWT Middleware)
You force the check before the controller code ever runs.

```typescript
// YOUR CODE (transaction.routes.ts)
router.use(authenticateToken); // Stops request here if no valid token
router.post('/send', sendMoney);
```

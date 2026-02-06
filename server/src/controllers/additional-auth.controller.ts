import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import * as crypto from 'crypto';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// In-memory stores
const sessions: { [sessionId: string]: any } = {};
const deactivatedAccounts: { [userId: string]: boolean } = {};
const usedOTPs: Set<string> = new Set();
const twoFAResetRequests: { [email: string]: string[] } = {};
const otpAttemptsBySession: { [sessionId: string]: number } = {};
const emailVerificationTokens: { [email: string]: string } = {};
const passwordResetTokens: { [email: string]: string[] } = {};
const rateLimitByIP: { [ip: string]: number } = {};
const rateLimitByUserAgent: { [ua: string]: number } = {};

// ============================================
// ADVANCED OTP/2FA BYPASSES
// ============================================

/**
 * VULNERABILITY 1: Account Deactivation → Password Reset Bypass
 * Deactivating account then resetting password bypasses 2FA
 * Source: HackerOne 2023-2024 Reports
 */
export const deactivateAccount = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        deactivatedAccounts[user.id] = true;

        res.json({
            message: 'Account deactivated',
            vulnerability: 'Deactivation does not invalidate 2FA requirement',
            exploit: 'Deactivate account, reset password, login without 2FA'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const loginAfterDeactivation = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // VULNERABILITY: Deactivated accounts can login without 2FA
        if (deactivatedAccounts[user.id]) {
            console.log('⚠️  VULNERABILITY: Deactivated account bypasses 2FA');
            const token = jwt.sign({ userId: user.id }, JWT_SECRET);
            return res.json({
                token,
                user: { id: user.id, email: user.email, name: user.name },
                vulnerability: 'Account deactivation bypasses 2FA requirement',
                exploit: 'Deactivate → Reset Password → Login without 2FA'
            });
        }

        res.json({ requiresOTP: true, message: '2FA required' });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 2: Reusable OTP (No Invalidation After Use)
 * OTPs remain valid after successful use
 * Source: HackerOne #2024 Microsoft Authenticator Report
 */
export const verifyOTPReusable = async (req: Request, res: Response) => {
    try {
        const { email, otp } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        // VULNERABILITY: Don't invalidate OTP after use
        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({
            token,
            user: { id: user.id, email: user.email, name: user.name },
            vulnerability: 'OTP not invalidated after use - can be reused',
            exploit: 'Intercept OTP, use it multiple times for replay attacks'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 3: Email OTP Bypass via Early Session Cookie
 * Session cookie issued before OTP verification
 * Source: HackerOne #2024 Drugs.com Report
 */
export const loginEarlySessionCookie = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // VULNERABILITY: Issue session cookie BEFORE 2FA verification
        const sessionId = `SESSION-${Date.now()}`;
        sessions[sessionId] = { userId: user.id, authenticated: true };

        res.cookie('sessionId', sessionId, { httpOnly: true });
        res.json({
            requiresOTP: true,
            message: 'OTP required',
            vulnerability: 'Session cookie issued before OTP verification',
            exploit: 'Use session cookie directly, skip OTP verification',
            sessionId
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 4: 2FA Bypass via Cookie Deletion
 * Deleting MFA cookie bypasses 2FA requirement
 * Source: HackerOne #2024 MFA Bypass Report
 */
export const loginWithMFACookie = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const sessionId = `SESSION-${Date.now()}`;
        sessions[sessionId] = { userId: user.id, mfaRequired: true };

        res.cookie('sessionId', sessionId, { httpOnly: true });
        res.cookie('mfa_required', 'true');

        res.json({
            requiresMFA: true,
            message: 'MFA required',
            vulnerability: 'MFA state stored in client-side cookie',
            exploit: 'Delete mfa_required cookie, keep sessionId, bypass MFA'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const accessWithoutMFA = async (req: Request, res: Response) => {
    try {
        const sessionId = req.cookies.sessionId;
        const mfaRequired = req.cookies.mfa_required;

        if (!sessionId || !sessions[sessionId]) {
            return res.status(401).json({ message: 'Not authenticated' });
        }

        // VULNERABILITY: Trust client-side cookie for MFA state
        if (mfaRequired === 'true') {
            return res.status(403).json({ message: 'MFA required' });
        }

        const session = sessions[sessionId];
        const user = await prisma.user.findUnique({ where: { id: session.userId } });

        res.json({
            message: 'Access granted',
            user: { id: user?.id, email: user?.email, name: user?.name },
            vulnerability: 'MFA bypassed by deleting client-side cookie'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 5: Expired TOTP Code Acceptance
 * TOTP codes accepted beyond valid time window
 * Source: HackerOne #2024 hackerone.com Report
 */
export const verifyTOTPExpired = async (req: Request, res: Response) => {
    try {
        const { email, totp, timestamp } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const now = Date.now();
        const totpAge = now - (timestamp || now);

        if (user.otp !== totp) {
            return res.status(400).json({ message: 'Invalid TOTP' });
        }

        // VULNERABILITY: Accept expired TOTP codes
        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({
            token,
            user: { id: user.id, email: user.email, name: user.name },
            vulnerability: 'Expired TOTP codes accepted',
            totpAge: `${Math.floor(totpAge / 1000)} seconds old`,
            exploit: 'Reuse old TOTP codes beyond valid time window'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 6: Bypassing Phone Number OTP in Account Recovery
 * Can add phone number without SMS verification
 * Source: HackerOne #2024 Report
 */
export const addRecoveryPhone = async (req: Request, res: Response) => {
    try {
        const { email, phoneNumber } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // VULNERABILITY: Add phone without SMS verification
        await prisma.user.update({
            where: { id: user.id },
            data: { name: `${user.name}|phone:${phoneNumber}` }
        });

        res.json({
            message: 'Recovery phone added',
            phoneNumber,
            vulnerability: 'Phone number added without SMS OTP verification',
            exploit: 'Add victim phone number, use for account recovery'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 7: 2FA Race Condition (Multiple Reset Requests)
 * Multiple 2FA reset requests remain active
 * Source: HackerOne #2024 2FA Reset Report
 */
export const request2FAReset = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const resetToken = crypto.randomBytes(16).toString('hex');

        if (!twoFAResetRequests[email]) {
            twoFAResetRequests[email] = [];
        }
        twoFAResetRequests[email].push(resetToken);

        res.json({
            message: '2FA reset request created',
            resetToken,
            activeRequests: twoFAResetRequests[email].length,
            vulnerability: 'Multiple 2FA reset requests remain active',
            exploit: 'Send multiple requests, cancel one, others remain valid for 24h'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const cancel2FAReset = async (req: Request, res: Response) => {
    try {
        const { email, resetToken } = req.body;

        // VULNERABILITY: Only remove the specific token
        if (twoFAResetRequests[email]) {
            const index = twoFAResetRequests[email].indexOf(resetToken);
            if (index > -1) {
                twoFAResetRequests[email].splice(index, 1);
            }
        }

        res.json({
            message: 'Reset request canceled',
            remainingRequests: twoFAResetRequests[email]?.length || 0,
            vulnerability: 'Other reset requests still active',
            exploit: 'Attacker can complete one of the remaining requests'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 8: OTP Brute Force via Session ID Rotation
 * Rate limiting tied to session ID
 * Source: Security Research
 */
export const newSession = async (req: Request, res: Response) => {
    const newSessionId = `SESSION-${Date.now()}-${Math.random()}`;
    res.cookie('sessionId', newSessionId);
    res.json({
        sessionId: newSessionId,
        message: 'New session created',
        vulnerability: 'Unlimited session creation allows rate limit bypass'
    });
};

export const verifyOTPWithSessionRateLimit = async (req: Request, res: Response) => {
    try {
        const { email, otp } = req.body;
        const sessionId = req.cookies.sessionId || 'default';

        // VULNERABILITY: Rate limit tied to session ID only
        if (otpAttemptsBySession[sessionId] >= 5) {
            return res.status(429).json({
                message: 'Too many OTP attempts',
                vulnerability: 'Rate limit tied to session - get new session to bypass',
                exploit: 'Request new session ID, continue brute force'
            });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || user.otp !== otp) {
            otpAttemptsBySession[sessionId] = (otpAttemptsBySession[sessionId] || 0) + 1;
            return res.status(400).json({
                message: 'Invalid OTP',
                attemptsRemaining: 5 - otpAttemptsBySession[sessionId]
            });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({
            token,
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// EMAIL VERIFICATION BYPASSES
// ============================================

/**
 * VULNERABILITY 9: Email Verification API Endpoint Bypass
 * Direct API access allows activation without verification
 * Source: Medium Bug Bounty Reports
 */
export const activateAccountDirect = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // VULNERABILITY: No authorization check
        await prisma.user.update({
            where: { id: user.id },
            data: { name: `${user.name}|verified` }
        });

        res.json({
            message: 'Account activated',
            vulnerability: 'Email verification bypassed via direct API access',
            exploit: 'Call activation endpoint without email verification token'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 10: Email Change Without Re-verification
 * Users can change email without verifying new email
 * Source: HackerOne Reports
 */
export const changeEmailNoVerification = async (req: Request, res: Response) => {
    try {
        const { currentEmail, newEmail } = req.body;

        const user = await prisma.user.findUnique({ where: { email: currentEmail } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // VULNERABILITY: Change email without verification
        await prisma.user.update({
            where: { id: user.id },
            data: { email: newEmail }
        });

        res.json({
            message: 'Email changed',
            newEmail,
            vulnerability: 'Email changed without verification of new address',
            exploit: 'Change to victim email, control account with unverified email'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 11: Email Verification Race Condition
 * Same OTP verifies both attacker and victim email
 * Source: HackerOne #2024
 */
export const requestEmailChange = async (req: Request, res: Response) => {
    try {
        const { email, newEmail } = req.body;

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        emailVerificationTokens[newEmail] = otp;

        res.json({
            message: 'Verification OTP sent',
            otp, // For demo
            vulnerability: 'Race condition in email verification',
            exploit: 'Send concurrent requests to verify both emails with same OTP'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const verifyEmailChange = async (req: Request, res: Response) => {
    try {
        const { email, otp } = req.body;

        // VULNERABILITY: No proper synchronization
        if (emailVerificationTokens[email] === otp) {
            delete emailVerificationTokens[email];
            res.json({
                message: 'Email verified',
                vulnerability: 'Race condition allows multiple emails verified with same OTP'
            });
        } else {
            res.status(400).json({ message: 'Invalid OTP' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 12: Front-end Only Email Verification
 * Server doesn't check email verification status
 * Source: Medium Security Research
 */
export const accessWithoutEmailVerification = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.userId;

        const user = await prisma.user.findUnique({ where: { id: userId } });

        // VULNERABILITY: No server-side email verification check
        res.json({
            message: 'Access granted',
            user: { id: user?.id, email: user?.email, name: user?.name },
            vulnerability: 'Email verification not enforced server-side',
            exploit: 'Access protected resources without verifying email'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// PASSWORD RESET FLAWS
// ============================================

/**
 * VULNERABILITY 13: Multiple Valid Reset Tokens
 * Multiple password reset tokens remain valid
 * Source: HackerOne Password Reset Reports
 */
export const requestPasswordResetMultiple = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const token = crypto.randomBytes(32).toString('hex');

        // VULNERABILITY: Don't invalidate old tokens
        if (!passwordResetTokens[email]) {
            passwordResetTokens[email] = [];
        }
        passwordResetTokens[email].push(token);

        res.json({
            message: 'Reset token sent',
            token,
            activeTokens: passwordResetTokens[email].length,
            vulnerability: 'Multiple reset tokens remain valid',
            exploit: 'Old tokens still work after new ones generated'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 14: Password Reset Race Condition
 * Concurrent reset requests exploitable
 * Source: HackerOne & Medium
 */
export const resetPasswordRaceCondition = async (req: Request, res: Response) => {
    try {
        const { email, token, newPassword } = req.body;

        // VULNERABILITY: No concurrency control
        if (passwordResetTokens[email]?.includes(token)) {
            const user = await prisma.user.findUnique({ where: { email } });
            if (user) {
                const hashedPassword = await bcrypt.hash(newPassword, 10);
                await prisma.user.update({
                    where: { id: user.id },
                    data: { password: hashedPassword }
                });

                res.json({
                    message: 'Password reset',
                    vulnerability: 'Race condition in password reset',
                    exploit: 'Send concurrent reset requests'
                });
            }
        } else {
            res.status(400).json({ message: 'Invalid token' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 15: 0-Click Account Takeover via Reset Flaw
 * Reset token sent to both emails due to race condition
 * Source: HackerOne #2024
 */
export const forgotPassword0Click = async (req: Request, res: Response) => {
    try {
        const { email, attackerEmail } = req.body;

        const token = crypto.randomBytes(32).toString('hex');

        // VULNERABILITY: Race condition sends token to both emails
        res.json({
            message: 'Reset token sent',
            token,
            sentTo: [email, attackerEmail],
            vulnerability: '0-click ATO - token sent to multiple emails',
            exploit: 'Exploit race condition to receive victim reset token'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 16: Password Reset Token in URL
 * Token in URL leaks via Referer header
 * Source: OWASP Best Practices
 */
export const resetPasswordURLToken = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const token = crypto.randomBytes(32).toString('hex');

        // VULNERABILITY: Token in URL
        const resetLink = `http://example.com/reset?token=${token}`;

        res.json({
            message: 'Reset link sent',
            resetLink,
            vulnerability: 'Reset token in URL - leaks via Referer header',
            exploit: 'Token leaked when user clicks external links on reset page'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// RATE LIMITING BYPASSES
// ============================================

/**
 * VULNERABILITY 17: Rate Limit Bypass via X-Forwarded-For
 * IP-based rate limiting trusts X-Forwarded-For header
 * Source: Security Research & HackerOne
 */
export const loginRateLimitXFF = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        const ip = req.headers['x-forwarded-for'] as string || req.ip || 'unknown';

        // VULNERABILITY: Trust X-Forwarded-For header
        if (rateLimitByIP[ip] >= 5) {
            return res.status(429).json({
                message: 'Too many attempts',
                vulnerability: 'Rate limit trusts X-Forwarded-For header',
                exploit: 'Change X-Forwarded-For header to bypass'
            });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            rateLimitByIP[ip] = (rateLimitByIP[ip] || 0) + 1;
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 18: Rate Limit Bypass via User-Agent Rotation
 * Rate limiting tied to User-Agent header
 * Source: Security Research
 */
export const loginRateLimitUserAgent = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        const userAgent = req.headers['user-agent'] || 'unknown';

        // VULNERABILITY: Rate limit includes User-Agent
        const key = `${email}-${userAgent}`;
        if (rateLimitByUserAgent[key] >= 5) {
            return res.status(429).json({
                message: 'Too many attempts',
                vulnerability: 'Rate limit tied to User-Agent',
                exploit: 'Rotate User-Agent strings to bypass'
            });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            rateLimitByUserAgent[key] = (rateLimitByUserAgent[key] || 0) + 1;
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 19: Rate Limit Bypass via Parameter Pollution
 * Random parameters make requests appear unique
 * Source: Security Research
 */
export const loginRateLimitParams = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        const fullUrl = req.originalUrl;

        // VULNERABILITY: Rate limit uses full URL including query params
        if (rateLimitByIP[fullUrl] >= 5) {
            return res.status(429).json({
                message: 'Too many attempts',
                vulnerability: 'Rate limit uses full URL',
                exploit: 'Add random query parameters to bypass'
            });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            rateLimitByIP[fullUrl] = (rateLimitByIP[fullUrl] || 0) + 1;
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY 20: Rate Limit Bypass via HTTP Method Switching
 * Rate limiting only applied to POST
 * Source: Security Research & WAF Bypass
 */
export const loginRateLimitMethodSwitch = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body || req.query;
        const method = req.method;

        // VULNERABILITY: Only rate limit POST requests
        if (method === 'POST' && rateLimitByIP[email] >= 5) {
            return res.status(429).json({
                message: 'Too many POST attempts',
                vulnerability: 'Rate limit only on POST',
                exploit: 'Switch to GET with query parameters to bypass'
            });
        }

        const user = await prisma.user.findUnique({ where: { email: email as string } });
        if (!user || !await bcrypt.compare(password as string, user.password)) {
            if (method === 'POST') {
                rateLimitByIP[email] = (rateLimitByIP[email] || 0) + 1;
            }
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

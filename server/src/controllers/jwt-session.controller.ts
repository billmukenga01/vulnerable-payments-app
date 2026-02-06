import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { z, ZodError } from 'zod';
import * as crypto from 'crypto';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const WEAK_JWT_SECRET = 'secret123'; // For weak secret vulnerability

// ============================================
// JWT VULNERABILITY CONTROLLERS
// ============================================

/**
 * Login with Weak JWT Secret
 * VULNERABILITY: Uses weak, brute-forceable secret
 */
export const loginWeakJWT = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // VULNERABILITY: Weak JWT secret
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            WEAK_JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: { id: user.id, email: user.email, name: user.name },
            vulnerability: 'Weak JWT secret - can be brute-forced with hashcat or john',
            exploit: `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// SESSION MANAGEMENT VULNERABILITIES
// ============================================

// In-memory session store (for demo purposes)
const sessions: { [sessionId: string]: any } = {};
let sessionCounter = 1000;

/**
 * VULNERABILITY: Session Fixation
 * Session ID not regenerated after login
 */
export const loginSessionFixation = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // VULNERABILITY: Don't regenerate session ID
        // Use existing session ID from cookie or create new one
        const sessionId = req.cookies.sessionId || `SESSION-${Date.now()}`;

        // Store session
        sessions[sessionId] = { userId: user.id, authenticated: true };

        res.cookie('sessionId', sessionId, { httpOnly: true });
        res.json({
            message: 'Logged in',
            sessionId,
            vulnerability: 'Session fixation - session ID not regenerated after login',
            exploit: 'Attacker can set victim\'s session ID before login, then hijack after victim authenticates'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY: Predictable Session IDs
 * Sequential session ID generation
 */
export const loginPredictableSession = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // VULNERABILITY: Predictable session ID
        const sessionId = `SESSION-${sessionCounter++}`;

        sessions[sessionId] = { userId: user.id };

        res.cookie('sessionId', sessionId);
        res.json({
            message: 'Logged in',
            sessionId,
            vulnerability: 'Predictable session ID - sequential counter',
            hint: `Next session will be: SESSION-${sessionCounter}`,
            exploit: 'Brute-force session IDs to hijack other users\' sessions'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY: No Session Invalidation on Logout
 * Session remains valid after logout
 */
export const logoutNoInvalidation = async (req: Request, res: Response) => {
    try {
        const sessionId = req.cookies.sessionId;

        // VULNERABILITY: Don't actually invalidate the session
        // Just clear client-side cookie
        // Session still exists in sessions object!

        res.clearCookie('sessionId');
        res.json({
            message: 'Logged out',
            vulnerability: 'Session not invalidated server-side',
            exploit: `Session ${sessionId} still valid - can be reused`,
            test: `curl -b "sessionId=${sessionId}" http://localhost:3000/api/auth/session-data`
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY: No Session Invalidation on Password Change
 * Existing sessions remain valid after password change
 */
export const changePasswordNoSessionInvalidation = async (req: Request, res: Response) => {
    try {
        const { currentPassword, newPassword } = req.body;
        // @ts-ignore
        const userId = req.userId;

        const user = await prisma.user.findUnique({ where: { id: userId } });

        if (!user || !await bcrypt.compare(currentPassword, user.password)) {
            return res.status(401).json({ message: 'Wrong password' });
        }

        // Update password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: userId },
            data: { password: hashedPassword }
        });

        // VULNERABILITY: Don't invalidate existing sessions/tokens

        res.json({
            message: 'Password changed',
            vulnerability: 'Old sessions/tokens still valid',
            exploit: 'Stolen JWT tokens remain valid even after password change'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Get session data (for testing session vulnerabilities)
 */
export const getSessionData = async (req: Request, res: Response) => {
    try {
        const sessionId = req.cookies.sessionId;

        if (!sessionId || !sessions[sessionId]) {
            return res.status(401).json({ message: 'Not authenticated' });
        }

        const session = sessions[sessionId];
        const user = await prisma.user.findUnique({ where: { id: session.userId } });

        res.json({
            message: 'Session valid',
            sessionId,
            user: { id: user?.id, email: user?.email, name: user?.name }
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// ADVANCED 2FA BYPASS VULNERABILITIES
// ============================================

/**
 * VULNERABILITY: 2FA Bypass via Blank/Null OTP
 * Sending blank or null OTP bypasses 2FA check
 * Source: HackerOne (Glassdoor report)
 */
export const verifyOTPBlankBypass = async (req: Request, res: Response) => {
    try {
        const { email, otp } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // VULNERABILITY: Blank OTP bypasses check
        if (!otp || otp === '' || otp === null || otp === undefined) {
            console.log('⚠️  VULNERABILITY: Blank OTP bypass - no verification performed');
            const token = jwt.sign({ userId: user.id }, JWT_SECRET);
            return res.json({
                token,
                user: { id: user.id, email: user.email, name: user.name },
                vulnerability: 'Blank OTP bypass - no OTP verification performed',
                exploit: 'Send empty/null OTP to bypass 2FA completely'
            });
        }

        // Normal OTP verification
        if (user.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY: Password Reset Poisoning (Host Header Injection)
 * Password reset link uses Host header, allowing attacker to steal reset tokens
 * Source: OWASP, HackerOne, PortSwigger
 */
export const forgotPasswordHostInjection = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');

        // Save token (in real app, would be in separate table)
        await prisma.user.update({
            where: { id: user.id },
            data: { otp: resetToken, otpExpires: new Date(Date.now() + 15 * 60 * 1000) }
        });

        // VULNERABILITY: Use Host header to build reset link
        const host = req.headers.host; // Attacker-controlled!
        const resetLink = `http://${host}/reset-password?token=${resetToken}`;

        // In real app, this would be emailed
        console.log(`⚠️  VULNERABILITY: Reset link uses attacker-controlled Host header`);
        console.log(`Reset link sent to ${email}: ${resetLink}`);

        res.json({
            message: 'Reset link sent',
            vulnerability: 'Host header injection',
            resetLink, // For demo purposes
            exploit: 'Change Host header to evil.com, victim receives link to evil.com, attacker steals token'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY: Account Lockout Bypass via Case Sensitivity
 * Account lockout only tracks exact email, can be bypassed with case variations
 * Source: OWASP, Bug Bounty reports
 */
const loginAttempts: { [email: string]: number } = {};

export const loginCaseSensitiveLockout = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        // VULNERABILITY: Case-sensitive lockout tracking
        if (loginAttempts[email] >= 5) {
            return res.status(429).json({
                message: 'Account locked due to too many failed attempts',
                vulnerability: 'Case-sensitive lockout - try different case to bypass'
            });
        }

        // Case-insensitive user lookup
        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase() }
        });

        if (!user || !await bcrypt.compare(password, user.password)) {
            loginAttempts[email] = (loginAttempts[email] || 0) + 1;
            return res.status(401).json({
                message: 'Invalid credentials',
                attemptsRemaining: 5 - loginAttempts[email]
            });
        }

        // Success
        delete loginAttempts[email];
        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({
            token,
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * VULNERABILITY: Credential Stuffing (No Global Rate Limiting)
 * Rate limiting per account, but not globally
 * Source: OWASP, HackerOne
 */
const perAccountAttempts: { [email: string]: number } = {};

export const loginNoGlobalRateLimit = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        // VULNERABILITY: Only per-account rate limiting
        if (perAccountAttempts[email] >= 5) {
            return res.status(429).json({
                message: 'Too many attempts for this account',
                vulnerability: 'No global rate limit - can test thousands of different accounts'
            });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user || !await bcrypt.compare(password, user.password)) {
            perAccountAttempts[email] = (perAccountAttempts[email] || 0) + 1;
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        delete perAccountAttempts[email];
        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({
            token,
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

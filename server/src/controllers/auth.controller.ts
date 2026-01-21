import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { z, ZodError } from 'zod';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

const registerSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
    name: z.string().min(2),
});

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string(),
});

export const register = async (req: Request, res: Response) => {
    try {
        const { email, password, name } = registerSchema.parse(req.body);

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                name,
                balance: 1000.0, // Initial balance bonus
            },
        });

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });

        res.status(201).json({ token, user: { id: user.id, email: user.email, name: user.name, balance: user.balance } });
    } catch (error) {
        if (error instanceof ZodError) {
            return res.status(400).json({ errors: (error as ZodError).errors });
        }
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = loginSchema.parse(req.body);

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // ============================================
        // 2FA FLOW: Generate OTP after password verification
        // ============================================

        // VULNERABILITY: Timing Attack
        await new Promise(resolve => setTimeout(resolve, 500));

        // VULNERABILITY: Weak OTP Generation (4 digits)
        const otp = Math.floor(1000 + Math.random() * 9000).toString();

        // Save OTP to database
        await prisma.user.update({
            where: { id: user.id },
            data: {
                otp,
                otpExpires: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes (but won't be enforced)
            }
        });

        // VULNERABILITY: OTP Disclosure
        // Return OTP in response (simulating email/SMS)
        res.json({
            message: 'Password verified. OTP sent for second factor authentication.',
            requiresOTP: true,
            otp, // CRITICAL VULNERABILITY: Exposing OTP
            email: user.email,
            expiresIn: '15 minutes',
            debug_info: 'In a real app, this OTP would be sent via email/SMS. Here it is exposed for testing.',
            vulnerabilities: [
                'OTP disclosed in response',
                'Weak 4-digit OTP',
                'Timing attack possible'
            ]
        });

    } catch (error) {
        if (error instanceof ZodError) {
            return res.status(400).json({ errors: (error as ZodError).errors });
        }
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const getMe = async (req: Request, res: Response) => {
    // @ts-ignore - userId attached by middleware
    const userId = req.userId;

    try {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ user: { id: user.id, email: user.email, name: user.name, balance: user.balance } });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const forgotPassword = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            // Vulnerable: User Enumeration (returns 404 if not found vs generic 200)
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save to DB (expires in 15 mins)
        await prisma.user.update({
            where: { id: user.id },
            data: {
                otp,
                otpExpires: new Date(Date.now() + 15 * 60 * 1000)
            }
        });

        // Vulnerability: Host Header Injection
        // We blindly trust the 'Host' header to construct the reset link.
        // An attacker can change this header to 'evil.com', poisoning the link.
        const host = req.get('x-forwarded-host') || req.get('host');
        const resetLink = `http://${host}/reset-password?email=${email}&otp=${otp}`;

        // MOCK: Return OTP and Poisoned Link in response
        res.json({
            message: 'OTP sent (mock)',
            otp, // Vulnerable: Leaking OTP
            resetLink, // Vulnerable: Poisoned Link
            debug_info: 'Normally this link would be emailed. Check "resetLink" for poisoning.'
        });

    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const resetPassword = async (req: Request, res: Response) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Validate OTP and Expiry
        if (user.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        // Vulnerability: OTP Expiry check is disabled (Infinite Validity)
        // if (user.otpExpires && new Date() > user.otpExpires) {
        //    return res.status(400).json({ message: 'OTP expired' });
        // }

        // Update Password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: user.id },
            data: {
                password: hashedPassword,
                otp: null,
                otpExpires: null
            }
        });

        res.json({ message: 'Password reset successful' });

    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// VULNERABLE OTP LOGIN IMPLEMENTATION
// ============================================

/**
 * Request OTP for Login
 * VULNERABILITIES:
 * 1. OTP Disclosure - Returns OTP in response
 * 2. Weak OTP Generation - Only 4 digits using Math.random()
 * 3. User Enumeration - Different responses for existing vs non-existing users
 * 4. Timing Attack - Artificial delay reveals valid emails
 */
export const requestOTP = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            // VULNERABILITY: User Enumeration
            // Different response for non-existent users
            return res.status(404).json({
                message: 'No account found with this email address',
                exists: false
            });
        }

        // VULNERABILITY: Timing Attack
        // Add artificial delay for existing users to make timing differences obvious
        await new Promise(resolve => setTimeout(resolve, 500));

        // VULNERABILITY: Weak OTP Generation
        // Using only 4 digits with Math.random() (predictable and brute-forceable)
        const otp = Math.floor(1000 + Math.random() * 9000).toString();

        // Save OTP to database
        await prisma.user.update({
            where: { id: user.id },
            data: {
                otp,
                otpExpires: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes (but won't be enforced)
            }
        });

        // VULNERABILITY: OTP Disclosure
        // Returning OTP in the response (simulating email display)
        res.json({
            message: 'OTP generated successfully',
            otp, // CRITICAL VULNERABILITY: Exposing OTP
            email: user.email,
            expiresIn: '15 minutes',
            debug_info: 'In a real app, this OTP would be sent via email/SMS. Here it is exposed for testing.',
            vulnerabilities: [
                'OTP disclosed in response',
                'Weak 4-digit OTP',
                'User enumeration possible',
                'Timing attack possible'
            ]
        });

    } catch (error) {
        console.error('Request OTP error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Verify OTP and Login (Second Factor)
 * This is called AFTER password verification in the login flow
 * VULNERABILITIES:
 * 1. No Rate Limiting - Unlimited verification attempts
 * 2. OTP Reuse - OTP is not invalidated after use
 * 3. Infinite Validity - Expiration check is disabled
 * 4. User Enumeration - Different error messages
 */
export const verifyOTP = async (req: Request, res: Response) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP are required' });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            // VULNERABILITY: User Enumeration
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.otp) {
            return res.status(400).json({ message: 'No OTP found. Please login with email and password first.' });
        }

        // VULNERABILITY: No Rate Limiting
        // An attacker can try unlimited OTP combinations

        if (user.otp !== otp) {
            // VULNERABILITY: Detailed error message helps attackers
            return res.status(400).json({
                message: 'Invalid OTP. Please try again.',
                attemptsRemaining: 'unlimited', // Highlighting the vulnerability
                hint: 'No rate limiting - you can try as many times as you want!'
            });
        }

        // VULNERABILITY: Infinite Validity
        // Expiration check is commented out - OTP never expires
        // if (user.otpExpires && new Date() > user.otpExpires) {
        //     return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
        // }

        // VULNERABILITY: OTP Reuse
        // We don't invalidate the OTP after successful use
        // In a secure implementation, we would set otp and otpExpires to null here

        // Generate JWT token (2FA complete)
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });

        res.json({
            message: 'Login successful - 2FA verified',
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                balance: user.balance
            },
            vulnerabilities: [
                'No rate limiting on OTP verification',
                'OTP can be reused (not invalidated)',
                'OTP never expires (expiration check disabled)'
            ]
        });

    } catch (error) {
        console.error('Verify OTP error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// 2FA BYPASS VULNERABILITIES
// ============================================

/**
 * Verify OTP with Response Manipulation Bypass
 * VULNERABILITY: Returns success structure even for wrong OTP
 * Attacker can intercept and modify the response
 */
export const verifyOTPBypass = async (req: Request, res: Response) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP are required' });
        }

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user || !user.otp) {
            return res.status(400).json({ message: 'Invalid request' });
        }

        const isValid = user.otp === otp;

        // VULNERABILITY: Response Manipulation
        // Even for wrong OTP, we return a 200 status with structured data
        // Attacker can intercept and change "verified: false" to "verified: true"
        if (!isValid) {
            return res.status(200).json({
                message: 'OTP verification attempted',
                verified: false,
                token: null,
                user: null,
                vulnerability: 'Response manipulation - attacker can change verified flag in intercepted response'
            });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });

        res.json({
            message: 'Login successful',
            verified: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                balance: user.balance
            }
        });

    } catch (error) {
        console.error('Verify OTP Bypass error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Remember Device - Bypass 2FA Permanently
 * VULNERABILITY: Sets a predictable cookie that can be forged
 */
export const rememberDevice = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.userId || req.body.userId;

        if (!userId) {
            return res.status(400).json({ message: 'User ID required' });
        }

        // VULNERABILITY: Predictable "remember me" token
        // Just base64 encoded user ID - can be forged for any user
        const rememberToken = Buffer.from(userId).toString('base64');

        // Set cookie for 30 days
        res.cookie('remember_2fa', rememberToken, {
            maxAge: 30 * 24 * 60 * 60 * 1000,
            httpOnly: false, // VULNERABILITY: Accessible via JavaScript
            secure: false    // VULNERABILITY: Not secure flag
        });

        res.json({
            message: 'Device remembered for 30 days',
            rememberToken,
            vulnerability: 'Token is just base64(userId) - can be forged for any user',
            exploit: `To bypass 2FA for user X, set cookie: remember_2fa=${Buffer.from('user-id-here').toString('base64')}`
        });

    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Check if device is remembered
 * VULNERABILITY: Trusts client-provided cookie without validation
 */
export const checkRememberedDevice = async (req: Request, res: Response) => {
    try {
        const rememberToken = req.cookies?.remember_2fa;

        if (!rememberToken) {
            return res.json({ remembered: false });
        }

        // VULNERABILITY: No validation of the token
        // Just decode and trust it
        try {
            const userId = Buffer.from(rememberToken, 'base64').toString();

            res.json({
                remembered: true,
                userId,
                vulnerability: 'No validation - any base64 string is accepted as valid'
            });
        } catch {
            res.json({ remembered: false });
        }

    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

// ============================================
// ENHANCED FORGOT PASSWORD VULNERABILITIES
// ============================================

/**
 * Forgot Password V2 - With Additional Vulnerabilities
 * NEW VULNERABILITIES:
 * 1. Weak token generation (predictable)
 * 2. Multiple active tokens allowed
 * 3. Tokens never invalidated
 */
let resetTokenCounter = 1000; // Global counter for predictable tokens

export const forgotPasswordV2 = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // VULNERABILITY: Weak Token Generation
        // Multiple weak methods - attacker can predict
        const weakTokens = {
            sequential: `RESET-${resetTokenCounter++}`,
            timestamp: `TOKEN-${Date.now()}`,
            base64Email: Buffer.from(email + Date.now()).toString('base64'),
        };

        // Use the sequential one (most predictable)
        const resetToken = weakTokens.sequential;

        // VULNERABILITY: Don't invalidate old tokens
        // Just add a new one, old ones remain valid
        // In a real app, we'd store this in a separate table
        // For demo, we'll just update the user record
        await prisma.user.update({
            where: { id: user.id },
            data: {
                otp: resetToken, // Reusing OTP field for reset token
                otpExpires: new Date(Date.now() + 15 * 60 * 1000)
            }
        });

        const host = req.get('x-forwarded-host') || req.get('host');
        const resetLink = `http://${host}/reset-password?email=${email}&token=${resetToken}`;

        res.json({
            message: 'Password reset token generated',
            token: resetToken,
            resetLink,
            weakTokens, // Show all weak generation methods
            vulnerabilities: [
                'Sequential token generation - predictable',
                'Timestamp-based token - can be guessed',
                'Multiple tokens can be active simultaneously',
                'Old tokens are never invalidated',
                'Token exposed in response'
            ],
            exploit: `Next token will be: RESET-${resetTokenCounter}`
        });

    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Reset Password V2 - With Additional Vulnerabilities
 * NEW VULNERABILITIES:
 * 1. No MFA check
 * 2. Race condition vulnerability
 * 3. Token reuse allowed
 */
export const resetPasswordV2 = async (req: Request, res: Response) => {
    try {
        const { email, token, newPassword } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // VULNERABILITY: No check if user has 2FA/MFA enabled
        // Should require additional verification if MFA is enabled

        // Validate token
        if (user.otp !== token) {
            return res.status(400).json({ message: 'Invalid reset token' });
        }

        // VULNERABILITY: No expiration check (already disabled)
        // VULNERABILITY: No race condition protection
        // Multiple concurrent requests could exploit timing

        // Simulate race condition window
        await new Promise(resolve => setTimeout(resolve, 100));

        // VULNERABILITY: Token not invalidated after use
        // Update password but keep token valid
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await prisma.user.update({
            where: { id: user.id },
            data: {
                password: hashedPassword,
                // NOT clearing otp and otpExpires - token reuse vulnerability
            }
        });

        res.json({
            message: 'Password reset successful',
            vulnerabilities: [
                'No MFA verification required',
                'Race condition - 100ms window for concurrent requests',
                'Token can be reused (not invalidated)',
                'No expiration check'
            ]
        });

    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Direct Dashboard Access - Bypass 2FA Check
 * VULNERABILITY: Doesn't verify if 2FA was completed
 * Only checks if user has a valid JWT token
 */
export const getDashboardData = async (req: Request, res: Response) => {
    try {
        // @ts-ignore - userId attached by auth middleware
        const userId = req.userId;

        // VULNERABILITY: No check if 2FA was completed
        // Just having a JWT is enough
        const user = await prisma.user.findUnique({ where: { id: userId } });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            message: 'Dashboard data accessed',
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                balance: user.balance
            },
            vulnerability: '2FA bypass - no verification that 2FA was completed, only JWT checked'
        });

    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};


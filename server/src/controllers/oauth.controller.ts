import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// Mock OAuth configurations
const OAUTH_CONFIGS = {
    google: {
        name: 'Google',
        authUrl: '/mock-oauth/google/authorize',
        tokenUrl: '/mock-oauth/google/token',
    },
    github: {
        name: 'GitHub',
        authUrl: '/mock-oauth/github/authorize',
        tokenUrl: '/mock-oauth/github/token',
    }
};

/**
 * Initiate OAuth Flow
 * VULNERABILITIES:
 * 1. Weak state generation (predictable)
 * 2. Accepts any redirect_uri (insufficient validation)
 */
export const initiateOAuth = async (req: Request, res: Response) => {
    try {
        const provider = req.params.provider as 'google' | 'github';
        const redirectUri = req.query.redirect_uri as string || 'http://localhost:5173/oauth/callback';

        if (!OAUTH_CONFIGS[provider]) {
            return res.status(400).json({ message: 'Invalid OAuth provider' });
        }

        // VULNERABILITY: Weak State Generation
        // Predictable state based on timestamp and provider
        const state = `STATE-${provider}-${Date.now()}`;

        // VULNERABILITY: No redirect_uri validation
        // Accepts ANY redirect_uri, including attacker-controlled domains
        // Should validate against whitelist

        const config = OAUTH_CONFIGS[provider];
        const authUrl = `${config.authUrl}?` +
            `client_id=mock_client_id&` +
            `redirect_uri=${encodeURIComponent(redirectUri)}&` +
            `state=${state}&` +
            `response_type=code&` +
            `scope=email profile`;

        res.json({
            authUrl,
            state,
            vulnerabilities: [
                'Weak state generation - predictable pattern',
                'No redirect_uri validation - accepts any URL',
                'State not stored server-side for validation'
            ]
        });

    } catch (error) {
        console.error('Initiate OAuth error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Handle OAuth Callback
 * VULNERABILITIES:
 * 1. No state validation (CSRF)
 * 2. Pre-account takeover
 * 3. No email verification
 * 4. Race condition in account linking
 * 5. Token leakage via redirect
 */
export const handleOAuthCallback = async (req: Request, res: Response) => {
    try {
        const { code, state, provider } = req.query;

        if (!code) {
            return res.status(400).json({ message: 'Authorization code required' });
        }

        // VULNERABILITY: No State Validation (CSRF)
        // Should validate state parameter against stored value
        // if (state !== storedState) { return error; }
        // This allows CSRF attacks where attacker initiates OAuth and victim completes it

        // Exchange code for token (simulated)
        const mockOAuthData = {
            provider: provider as string || 'google',
            oauthId: `oauth_${code}_${Date.now()}`,
            email: `user_${code}@example.com`,
            name: `User ${code}`,
        };

        // VULNERABILITY: Pre-Account Takeover
        // Find user by email without verification
        let user = await prisma.user.findUnique({
            where: { email: mockOAuthData.email }
        });

        // VULNERABILITY: Race Condition
        // No locking mechanism - concurrent requests can cause issues
        await new Promise(resolve => setTimeout(resolve, 100));

        if (user) {
            // VULNERABILITY: Automatic Account Linking
            // Links OAuth to existing account without verification
            // Attacker could have pre-registered with victim's email
            user = await prisma.user.update({
                where: { id: user.id },
                data: {
                    oauthProvider: mockOAuthData.provider,
                    oauthId: mockOAuthData.oauthId,
                    oauthEmail: mockOAuthData.email,
                    // NOT setting emailVerified to true
                }
            });
        } else {
            // Create new user
            user = await prisma.user.create({
                data: {
                    email: mockOAuthData.email,
                    password: 'oauth_no_password', // OAuth users don't have password
                    name: mockOAuthData.name,
                    balance: 1000.0,
                    oauthProvider: mockOAuthData.provider,
                    oauthId: mockOAuthData.oauthId,
                    oauthEmail: mockOAuthData.email,
                    emailVerified: false, // VULNERABILITY: Not verified
                }
            });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });

        // VULNERABILITY: Token Leakage via URL
        // Tokens in URL can leak via Referer header
        const redirectUrl = `/oauth/success?token=${token}&oauth_token=${mockOAuthData.oauthId}&state=${state}`;

        res.json({
            success: true,
            redirectUrl,
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                balance: user.balance
            },
            vulnerabilities: [
                'No state validation - CSRF vulnerable',
                'Pre-account takeover - links to existing email without verification',
                'Race condition - no locking on account linking',
                'No email verification required',
                'Token leakage - tokens in URL parameters'
            ]
        });

    } catch (error) {
        console.error('OAuth callback error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

/**
 * Link OAuth Account to Existing User
 * VULNERABILITIES:
 * 1. No verification that user owns the OAuth email
 * 2. Race condition
 */
export const linkOAuthAccount = async (req: Request, res: Response) => {
    try {
        // @ts-ignore
        const userId = req.userId;
        const { provider, oauthId, oauthEmail } = req.body;

        if (!userId || !provider || !oauthId) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // VULNERABILITY: No verification
        // Should send verification email to oauthEmail
        // Should verify user actually owns this OAuth account

        // VULNERABILITY: Race condition
        await new Promise(resolve => setTimeout(resolve, 100));

        const user = await prisma.user.update({
            where: { id: userId },
            data: {
                oauthProvider: provider,
                oauthId,
                oauthEmail,
            }
        });

        res.json({
            message: 'OAuth account linked',
            user: {
                id: user.id,
                email: user.email,
                oauthProvider: user.oauthProvider
            },
            vulnerabilities: [
                'No verification that user owns OAuth account',
                'Race condition in linking process',
                'No email verification sent'
            ]
        });

    } catch (error) {
        console.error('Link OAuth error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

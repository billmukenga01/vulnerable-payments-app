import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        // @ts-ignore
        req.userId = user.userId;
        next();
    });
};

// ============================================
// JWT VULNERABILITY MIDDLEWARE
// ============================================

/**
 * VULNERABILITY 1: JWT None Algorithm Bypass
 * Accepts JWTs with alg: "none", allowing unsigned tokens
 * Source: OWASP, PortSwigger, Medium
 */
export const authenticateTokenNoneAlg = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        // VULNERABILITY: Decode without verification if alg is "none"
        const decoded = jwt.decode(token, { complete: true }) as any;

        if (decoded?.header.alg === 'none') {
            // Accept unsigned tokens!
            console.log('⚠️  VULNERABILITY: Accepting unsigned JWT with alg=none');
            // @ts-ignore
            req.userId = decoded.payload.userId;
            return next();
        }

        // Normal verification for other algorithms
        jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid token' });
            }
            // @ts-ignore
            req.userId = user.userId;
            next();
        });
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
};

/**
 * VULNERABILITY 2: JWT Weak Secret
 * Uses a weak, easily brute-forceable secret
 * Source: HackerOne, OWASP
 */
const WEAK_JWT_SECRET = 'secret123'; // VULNERABILITY: Weak secret

export const authenticateTokenWeakSecret = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, WEAK_JWT_SECRET, (err: any, user: any) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        console.log('⚠️  VULNERABILITY: Using weak JWT secret - can be brute-forced');
        // @ts-ignore
        req.userId = user.userId;
        next();
    });
};

/**
 * VULNERABILITY 3: JWT Algorithm Confusion (RS256 → HS256)
 * Accepts both RS256 and HS256, allowing public key to be used as HMAC secret
 * Source: PortSwigger, Medium
 */
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWC
jPBc9/cPMmJPvNNhLGPJNKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPn
zJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMP
nzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKM
PnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJK
MPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJKMPnzJKEQCJPJ
KQIDAQAB
-----END PUBLIC KEY-----`; // Mock public key

export const authenticateTokenAlgConfusion = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.decode(token, { complete: true }) as any;

        // VULNERABILITY: Accept multiple algorithms without strict checking
        if (decoded?.header.alg === 'HS256') {
            jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
                if (err) {
                    return res.status(403).json({ message: 'Invalid token' });
                }
                // @ts-ignore
                req.userId = user.userId;
                next();
            });
        } else if (decoded?.header.alg === 'RS256') {
            // VULNERABILITY: Could use public key as HMAC secret
            console.log('⚠️  VULNERABILITY: Algorithm confusion possible - RS256 accepted');
            jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] }, (err: any, user: any) => {
                if (err) {
                    // Try with public key as HMAC secret (the actual vulnerability)
                    try {
                        const verified = jwt.verify(token, PUBLIC_KEY, { algorithms: ['HS256'] }) as any;
                        // @ts-ignore
                        req.userId = verified.userId;
                        return next();
                    } catch {
                        return res.status(403).json({ message: 'Invalid token' });
                    }
                }
                // @ts-ignore
                req.userId = user.userId;
                next();
            });
        } else {
            res.status(403).json({ message: 'Unsupported algorithm' });
        }
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
};

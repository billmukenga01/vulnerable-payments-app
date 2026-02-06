import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import * as fs from 'fs';
import * as path from 'path';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// ============================================
// JWT KID INJECTION VULNERABILITIES
// ============================================

/**
 * VULNERABILITY 4: JWT kid SQL Injection
 * Uses kid parameter in SQL query without sanitization
 * Source: HackerOne, Acunetix, Invicti
 */
export const authenticateTokenKidSQLi = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.decode(token, { complete: true }) as any;
        const kid = decoded?.header.kid || 'default';

        // VULNERABILITY: SQL Injection via kid parameter
        console.log(`⚠️  VULNERABILITY: Using kid in SQL query: ${kid}`);

        try {
            // Simulate SQL injection vulnerability
            const query = `SELECT secret FROM keys WHERE kid = '${kid}'`;
            console.log(`Executing query: ${query}`);

            // For demo: if kid contains SQL injection, use a known secret
            let secret = JWT_SECRET;
            if (kid.includes('UNION') || kid.includes('--') || kid.includes("'")) {
                console.log('⚠️  SQL Injection detected in kid parameter!');
                secret = 'known_secret'; // Attacker can inject this
            }

            const verified = jwt.verify(token, secret) as any;
            // @ts-ignore
            req.userId = verified.userId;
            next();
        } catch (error) {
            res.status(403).json({ message: 'Invalid token' });
        }
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
};

/**
 * VULNERABILITY 5: JWT kid Path Traversal
 * Uses kid parameter to load key file, allowing path traversal
 * Source: PortSwigger, Vaadata
 */
export const authenticateTokenKidPathTraversal = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.decode(token, { complete: true }) as any;
        const kid = decoded?.header.kid || 'default';

        // VULNERABILITY: Path traversal
        console.log(`⚠️  VULNERABILITY: Loading key from path: ./keys/${kid}.pem`);

        let secret = JWT_SECRET;

        try {
            // Simulate path traversal vulnerability
            const keyPath = path.join('./keys', `${kid}.pem`);

            // For demo: if kid contains path traversal, use empty string
            if (kid.includes('..') || kid.includes('/dev/null')) {
                console.log('⚠️  Path traversal detected in kid parameter!');
                secret = ''; // Content of /dev/null or empty file
            }

            const verified = jwt.verify(token, secret) as any;
            // @ts-ignore
            req.userId = verified.userId;
            next();
        } catch (error) {
            res.status(403).json({ message: 'Invalid token' });
        }
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
};

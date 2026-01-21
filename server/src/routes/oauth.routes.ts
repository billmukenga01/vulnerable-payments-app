import { Router } from 'express';
import { initiateOAuth, handleOAuthCallback, linkOAuthAccount } from '../controllers/oauth.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();

// OAuth initiation
router.get('/initiate/:provider', initiateOAuth);

// OAuth callback
router.get('/callback', handleOAuthCallback);

// Link OAuth account to existing user
router.post('/link', authenticateToken, linkOAuthAccount);

export default router;

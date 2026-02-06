import { Router } from 'express';
import {
    loginWeakJWT,
    loginSessionFixation,
    loginPredictableSession,
    logoutNoInvalidation,
    changePasswordNoSessionInvalidation,
    getSessionData,
    verifyOTPBlankBypass,
    forgotPasswordHostInjection,
    loginCaseSensitiveLockout,
    loginNoGlobalRateLimit
} from '../controllers/jwt-session.controller';
import {
    authenticateToken,
    authenticateTokenNoneAlg,
    authenticateTokenWeakSecret,
    authenticateTokenAlgConfusion
} from '../middleware/auth.middleware';
import {
    authenticateTokenKidSQLi,
    authenticateTokenKidPathTraversal
} from '../middleware/jwt.middleware';

const router = Router();

// ============================================
// JWT VULNERABILITY ENDPOINTS
// ============================================

// Login with weak JWT secret
router.post('/login-weak-jwt', loginWeakJWT);

// Protected endpoint using none algorithm middleware
router.get('/me-none-alg', authenticateTokenNoneAlg, (req, res) => {
    // @ts-ignore
    res.json({ userId: req.userId, vulnerability: 'JWT none algorithm accepted' });
});

// Protected endpoint using weak secret middleware
router.get('/me-weak-secret', authenticateTokenWeakSecret, (req, res) => {
    // @ts-ignore
    res.json({ userId: req.userId, vulnerability: 'Weak JWT secret' });
});

// Protected endpoint using algorithm confusion middleware
router.get('/me-alg-confusion', authenticateTokenAlgConfusion, (req, res) => {
    // @ts-ignore
    res.json({ userId: req.userId, vulnerability: 'Algorithm confusion possible' });
});

// Protected endpoint using kid SQL injection middleware
router.get('/me-kid-sqli', authenticateTokenKidSQLi, (req, res) => {
    // @ts-ignore
    res.json({ userId: req.userId, vulnerability: 'kid SQL injection' });
});

// Protected endpoint using kid path traversal middleware
router.get('/me-kid-path', authenticateTokenKidPathTraversal, (req, res) => {
    // @ts-ignore
    res.json({ userId: req.userId, vulnerability: 'kid path traversal' });
});

// ============================================
// SESSION MANAGEMENT VULNERABILITY ENDPOINTS
// ============================================

// Session fixation login
router.post('/login-session-fixation', loginSessionFixation);

// Predictable session ID login
router.post('/login-predictable-session', loginPredictableSession);

// Logout without session invalidation
router.post('/logout-no-invalidation', logoutNoInvalidation);

// Change password without session invalidation
router.post('/change-password-no-invalidation', authenticateToken, changePasswordNoSessionInvalidation);

// Get session data (for testing)
router.get('/session-data', getSessionData);

// ============================================
// ADVANCED 2FA BYPASS ENDPOINTS
// ============================================

// 2FA bypass via blank OTP
router.post('/verify-otp-blank-bypass', verifyOTPBlankBypass);

// ============================================
// ADDITIONAL AUTHENTICATION BYPASS ENDPOINTS
// ============================================

// Password reset with host header injection
router.post('/forgot-password-host-injection', forgotPasswordHostInjection);

// Login with case-sensitive lockout bypass
router.post('/login-case-sensitive-lockout', loginCaseSensitiveLockout);

// Login with no global rate limit (credential stuffing)
router.post('/login-no-global-limit', loginNoGlobalRateLimit);

export default router;

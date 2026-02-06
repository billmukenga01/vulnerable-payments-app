import express from 'express';
import * as additionalAuthController from '../controllers/additional-auth.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = express.Router();

// ============================================
// ADVANCED OTP/2FA BYPASSES
// ============================================

// Vulnerability 1: Account Deactivation Bypass
router.post('/deactivate-account', additionalAuthController.deactivateAccount);
router.post('/login-after-deactivation', additionalAuthController.loginAfterDeactivation);

// Vulnerability 2: Reusable OTP
router.post('/verify-otp-reusable', additionalAuthController.verifyOTPReusable);

// Vulnerability 3: Early Session Cookie
router.post('/login-early-session-cookie', additionalAuthController.loginEarlySessionCookie);

// Vulnerability 4: Cookie Deletion Bypass
router.post('/login-mfa-cookie', additionalAuthController.loginWithMFACookie);
router.get('/access-without-mfa', additionalAuthController.accessWithoutMFA);

// Vulnerability 5: Expired TOTP
router.post('/verify-totp-expired', additionalAuthController.verifyTOTPExpired);

// Vulnerability 6: Phone Number Bypass
router.post('/add-recovery-phone', additionalAuthController.addRecoveryPhone);

// Vulnerability 7: 2FA Race Condition
router.post('/request-2fa-reset', additionalAuthController.request2FAReset);
router.post('/cancel-2fa-reset', additionalAuthController.cancel2FAReset);

// Vulnerability 8: Session ID Rotation
router.get('/new-session', additionalAuthController.newSession);
router.post('/verify-otp-session-limit', additionalAuthController.verifyOTPWithSessionRateLimit);

// ============================================
// EMAIL VERIFICATION BYPASSES
// ============================================

// Vulnerability 9: Direct API Bypass
router.post('/activate-account-direct', additionalAuthController.activateAccountDirect);

// Vulnerability 10: Email Change Without Verification
router.post('/change-email-no-verification', additionalAuthController.changeEmailNoVerification);

// Vulnerability 11: Email Verification Race Condition
router.post('/request-email-change', additionalAuthController.requestEmailChange);
router.post('/verify-email-change', additionalAuthController.verifyEmailChange);

// Vulnerability 12: Front-end Only Verification
router.get('/access-without-email-verification', authenticateToken, additionalAuthController.accessWithoutEmailVerification);

// ============================================
// PASSWORD RESET FLAWS
// ============================================

// Vulnerability 13: Multiple Valid Tokens
router.post('/request-password-reset-multiple', additionalAuthController.requestPasswordResetMultiple);

// Vulnerability 14: Password Reset Race Condition
router.post('/reset-password-race-condition', additionalAuthController.resetPasswordRaceCondition);

// Vulnerability 15: 0-Click Account Takeover
router.post('/forgot-password-0click', additionalAuthController.forgotPassword0Click);

// Vulnerability 16: Token in URL
router.post('/reset-password-url-token', additionalAuthController.resetPasswordURLToken);

// ============================================
// RATE LIMITING BYPASSES
// ============================================

// Vulnerability 17: X-Forwarded-For Bypass
router.post('/login-rate-limit-xff', additionalAuthController.loginRateLimitXFF);

// Vulnerability 18: User-Agent Bypass
router.post('/login-rate-limit-ua', additionalAuthController.loginRateLimitUserAgent);

// Vulnerability 19: Parameter Pollution Bypass
router.post('/login-rate-limit-params', additionalAuthController.loginRateLimitParams);

// Vulnerability 20: HTTP Method Switching
router.post('/login-rate-limit-method', additionalAuthController.loginRateLimitMethodSwitch);
router.get('/login-rate-limit-method', additionalAuthController.loginRateLimitMethodSwitch);

export default router;

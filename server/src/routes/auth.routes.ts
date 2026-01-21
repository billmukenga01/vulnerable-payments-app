import { Router } from 'express';
import {
    register,
    login,
    getMe,
    forgotPassword,
    resetPassword,
    requestOTP,
    verifyOTP,
    verifyOTPBypass,
    rememberDevice,
    checkRememberedDevice,
    forgotPasswordV2,
    resetPasswordV2,
    getDashboardData
} from '../controllers/auth.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();

// Original routes
router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/request-otp', requestOTP);
router.post('/verify-otp', verifyOTP);
router.get('/me', authenticateToken, getMe);

// 2FA Bypass Vulnerabilities
router.post('/verify-otp-bypass', verifyOTPBypass);
router.post('/remember-device', rememberDevice);
router.get('/check-remembered', checkRememberedDevice);

// Enhanced Forgot Password Vulnerabilities
router.post('/forgot-password-v2', forgotPasswordV2);
router.post('/reset-password-v2', resetPasswordV2);

// Direct endpoint access (should require 2FA but doesn't)
router.get('/dashboard-data', authenticateToken, getDashboardData);

export default router;

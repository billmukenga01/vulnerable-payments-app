import { Router } from 'express';
import { mockAuthorize, mockToken, mockUserInfo } from '../controllers/mock-oauth.controller';

const router = Router();

// Mock OAuth provider endpoints
router.get('/:provider/authorize', mockAuthorize);
router.post('/:provider/token', mockToken);
router.get('/:provider/userinfo', mockUserInfo);

export default router;

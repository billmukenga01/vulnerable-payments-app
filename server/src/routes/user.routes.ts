import { Router } from 'express';
import { getUser, getBalance } from '../controllers/user.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();

router.use(authenticateToken);

router.get('/:id', getUser);
router.get('/:id/balance', getBalance);

export default router;

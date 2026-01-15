import { Router } from 'express';
import { sendMoney, getHistory } from '../controllers/transaction.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();

router.use(authenticateToken);

router.post('/send', sendMoney);
router.get('/history', getHistory);

export default router;

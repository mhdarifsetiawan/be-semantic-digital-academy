import { Router } from 'express';
import { authenticateToken } from '../../middleware/auth';
import { getMe } from '../../controllers/userController';

const router = Router();

router.get('/me', authenticateToken, getMe);

export default router;

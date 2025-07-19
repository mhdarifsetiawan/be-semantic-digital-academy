import { Router } from 'express';

import { login, logout, refreshToken, register } from '../../controllers/authController';
import { authRateLimiter } from '../../middleware/rateLimiter';

const router = Router();

router.post('/login', authRateLimiter, login);
router.post('/register', authRateLimiter, register);
router.post('/logout', authRateLimiter, logout);
router.post('/refresh-token', authRateLimiter, refreshToken);

export default router;

import { Router } from 'express';
import { login, register, logout, refreshToken } from '../../controllers/authController';
import { authRateLimiter } from '../../middleware/rateLimiter';
import { asyncHandler } from '../../utils/asyncHandler';

const router = Router();

router.post('/login', authRateLimiter, login);
router.post('/register', authRateLimiter, register);
router.post('/logout', authRateLimiter, logout);
router.post('/refresh-token', authRateLimiter, refreshToken);

export default router;

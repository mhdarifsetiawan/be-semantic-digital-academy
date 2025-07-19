import { Router } from 'express';

import { login, logout, refreshToken, register } from '../../controllers/authController';
import { authRateLimiter } from '../../middleware/rateLimiter';
import { flexiblePayloadValidator } from '../../middleware/validator/paylodValidator';

const router = Router();

router.post('/login', authRateLimiter, flexiblePayloadValidator, login);
router.post('/register', authRateLimiter, register);
router.post('/logout', authRateLimiter, logout);
router.post('/refresh-token', authRateLimiter, refreshToken);

export default router;

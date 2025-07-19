// src/middleware/rateLimiter.ts
import rateLimit from 'express-rate-limit';

export const authRateLimiter = rateLimit({
    legacyHeaders: false,
    max: 1000, // max 10 request per IP
    message: {
        message: 'Too many attempts, please try again later.',
    },
    standardHeaders: true,
    windowMs: 15 * 60 * 1000, // 15 menit
});

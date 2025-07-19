// src/middleware/loggerMiddleware.ts
import { NextFunction, Request, Response } from 'express';

import logger from '../utils/logger';

export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();

    const ip = req.headers['x-forwarded-for'] ?? req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    logger.info(`Incoming request: ${req.method} ${req.originalUrl}`);
    logger.info(`IP: ${ip} | User-Agent: ${userAgent}`);

    res.on('finish', () => {
        const duration = Date.now() - start;
        const message = `${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`;

        if (res.statusCode >= 500) {
            logger.error(message);
        } else if (res.statusCode >= 400) {
            logger.warn(message);
        } else {
            logger.info(message);
        }
    });

    next();
};

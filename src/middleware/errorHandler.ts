// src/middleware/errorHandler.ts
import { NextFunction, Request, Response } from 'express';

import { ApiError } from '../utils/ApiError';
import logger from '../utils/logger';

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
    if (err instanceof ApiError) {
        logger.error(`Handle Error: ${String(err.message)}`);

        return res.status(err.statusCode).json({ message: err.message });
    }

    logger.error(`Unhandled Error: ${String(err)}`);
    return res.status(500).json({ message: 'Internal server error' });
}

// src/middleware/errorHandler.ts
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
    if (err instanceof ApiError) {
        return res.status(err.statusCode).json({ message: err.message });
    }

    console.error('Unhandled error:', err);
    return res.status(500).json({ message: 'Internal server error' });
}

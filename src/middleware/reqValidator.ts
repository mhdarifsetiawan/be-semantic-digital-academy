import { NextFunction, Response } from 'express';

import { TypedRequestBody } from '../types/request';
import { ApiError } from '../utils/ApiError';
import logger from '../utils/logger';

// Tipe eksplisit untuk payload login
interface LoginRequestBody {
    email: string;
    password: string;
}

// Middleware validasi login payload
export const reqValidator = (req: TypedRequestBody<Partial<LoginRequestBody>>, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) {
        logger.info('Middleware: Missing email or password in request body');
        next(new ApiError('Email and password are required', 400));
        return;
    }

    // Simpan payload ke res.locals agar bisa diakses controller
    res.locals.loginData = { email, password };

    logger.info('Middleware: Login payload validated');
    next();
};

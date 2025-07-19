// src/controllers/authController.ts
import { Request, Response } from 'express';
import ms from 'ms';

import { loginUser, registerUser, removeRefreshToken, validateRefreshTokenAndGenerateAccess } from '../services/authService';
import { ApiError } from '../utils/ApiError';
import { asyncHandler } from '../utils/asyncHandler';
import logger from '../utils/logger';

interface LoginRequestBody {
    email: string;
    password: string;
}

export const login = asyncHandler(async (req: Request<object, object, LoginRequestBody>, res: Response) => {
    const payload = res.locals.payload as LoginRequestBody;
    const { email, password } = payload;

    if (!email || !password) {
        logger.info('Controller: Missing email or password in request body');
        throw new ApiError('Email and password are required', 400);
    }

    logger.info('Controller: login user started');
    const { accessToken, refreshToken } = await loginUser(email, password);

    const ACCESS_TOKEN_MAX_AGE = process.env.ACCESS_TOKEN_EXPIRES_IN ?? '15m';
    const REFRESH_TOKEN_MAX_AGE = process.env.REFRESH_TOKEN_EXPIRES_IN ?? '7d';

    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        maxAge: ms(ACCESS_TOKEN_MAX_AGE),
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
    })
        .cookie('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: ms(REFRESH_TOKEN_MAX_AGE) as number,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production',
        })
        .json({ message: 'Login successful' });
});

interface RegisterRequestBody {
    email: string;
    name: string;
    password: string;
}

export const register = asyncHandler(async (req: Request<object, object, RegisterRequestBody>, res: Response) => {
    const { email, name, password } = req.body;

    if (!email || !password || !name) {
        throw new ApiError('Email, password, and name are required', 400);
    }

    const user = (await registerUser(email, password, name)) as { email: string; id: string; name: string };
    res.status(201).json({ user });
});

export const logout = asyncHandler(async (req: Request, res: Response) => {
    const refreshToken = (req.cookies as Record<string, string | undefined>).refreshToken;

    if (refreshToken) {
        await removeRefreshToken(refreshToken);
    }

    res.clearCookie('accessToken', {
        httpOnly: true,
        path: '/',
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
    })
        .clearCookie('refreshToken', {
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production',
        })
        .status(200)
        .json({ message: 'Logged out successfully' });
});

export const refreshToken = asyncHandler(async (req: Request, res: Response) => {
    const token = (req.cookies as Record<string, string | undefined>).refreshToken;
    if (!token) {
        console.info('Refresh token is missing');
        throw new ApiError('Refresh token is missing', 401);
    }

    const newAccessToken = await validateRefreshTokenAndGenerateAccess(token);

    res.cookie('accessToken', newAccessToken, {
        httpOnly: true,
        maxAge: 15 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production',
    });

    res.json({ message: 'Access token refreshed' });
});

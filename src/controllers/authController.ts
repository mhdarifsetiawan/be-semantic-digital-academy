// src/controllers/authController.ts
import { Request, Response } from 'express';
import { loginUser, registerUser, removeRefreshToken, validateRefreshTokenAndGenerateAccess } from '../services/authService';
import { asyncHandler } from '../utils/asyncHandler';
import { ApiError } from '../utils/ApiError';

export const login = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
        throw new ApiError('Email and password are required', 400);
    }

    const { accessToken, refreshToken } = await loginUser(email, password);

    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 15 * 60 * 1000,
    })
        .cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        })
        .json({ message: 'Login successful' });
});

export const register = asyncHandler(async (req: Request, res: Response) => {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
        throw new ApiError('Email, password, and name are required', 400);
    }

    const user = await registerUser(email, password, name);
    res.status(201).json({ user });
});

export const logout = asyncHandler(async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
        await removeRefreshToken(refreshToken);
    }

    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
    })
        .clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
        })
        .status(200)
        .json({ message: 'Logged out successfully' });
});

export const refreshToken = asyncHandler(async (req: Request, res: Response) => {
    const token = req.cookies.refreshToken;
    if (!token) {
        throw new ApiError('Refresh token is missing', 401);
    }

    const newAccessToken = await validateRefreshTokenAndGenerateAccess(token);

    res.cookie('accessToken', newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 15 * 60 * 1000,
    });

    res.json({ message: 'Access token refreshed' });
});

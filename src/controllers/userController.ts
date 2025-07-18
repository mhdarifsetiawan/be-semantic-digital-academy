// src/controllers/userController.ts
import { Response } from 'express';
import { getUserById } from '../services/userService';
import { AuthRequest } from '../middleware/auth';
import { asyncHandler } from '../utils/asyncHandler';
import { ApiError } from '../utils/ApiError';

export const getMe = asyncHandler(async (req: AuthRequest, res: Response) => {
    const userId = req.userId!; // Sudah divalidasi oleh middleware auth

    if (!userId) {
        throw new ApiError('userId are required', 400);
    }

    const user = await getUserById(userId);
    res.json({ user });
});

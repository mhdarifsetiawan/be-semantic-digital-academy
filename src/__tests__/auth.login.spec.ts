/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import app from '../app';
import { pool } from '../db/pools';
import { loginUser } from '../services/authService';
import { ApiError } from '../utils/ApiError';
import * as tokenUtils from '../utils/token';

// Helper untuk generate random token seperti JWT
function generateFakeToken(type: 'access' | 'refresh') {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
        JSON.stringify({
            exp: Math.floor(Date.now() / 1000) + (type === 'access' ? 900 : 604800), // 15m / 7d
            iat: Math.floor(Date.now() / 1000),
            sub: `user-${Math.random().toString(36).substring(2, 8)}`,
            type,
        }),
    ).toString('base64url');
    const signature = crypto.randomBytes(32).toString('base64url');
    return `${header}.${payload}.${signature}`;
}

vi.mock('../db/pools');
vi.mock('bcrypt');
vi.mock('../utils/token');

describe('loginUser', () => {
    const email = 'test@example.com';
    const password = 'password123';
    const hashedPassword = '$2b$10$somethinghashed';
    const mockUser = { email, id: 'user-123', password: hashedPassword };

    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('should throw error if user not found', async () => {
        (pool.query as any).mockResolvedValue({ rows: [] });

        console.log('should throw error if user not found');
        console.log('Request: ', mockUser);
        console.log('Response: ', {
            message: 'Invalid email or password',
            statusCode: 401,
        });

        await expect(loginUser(email, password)).rejects.toThrowError(ApiError);
        await expect(loginUser(email, password)).rejects.toMatchObject({
            message: 'Invalid email or password',
            statusCode: 401,
        });
    });

    it('should throw error if password does not match', async () => {
        (pool.query as any).mockResolvedValue({ rows: [mockUser] });
        (bcrypt.compare as any).mockResolvedValue(false);

        console.log('should throw error if password does not match');
        console.log('Request: ', mockUser);
        console.log('Response: ', {
            message: 'Invalid email or password',
            statusCode: 401,
        });

        await expect(loginUser(email, password)).rejects.toThrowError(ApiError);
        await expect(loginUser(email, password)).rejects.toMatchObject({
            message: 'Invalid email or password',
            statusCode: 401,
        });
    });

    it('should return tokens if login successful', async () => {
        const fakeAccess = generateFakeToken('access');
        const fakeRefresh = generateFakeToken('refresh');

        (pool.query as any).mockResolvedValue({ rows: [mockUser] });
        (bcrypt.compare as any).mockResolvedValue(true);
        vi.spyOn(tokenUtils, 'generateAccessToken').mockReturnValue(fakeAccess);
        vi.spyOn(tokenUtils, 'generateRefreshToken').mockResolvedValue(fakeRefresh);

        const result = await loginUser(email, password);

        console.log('should return tokens if login successful');
        console.log('Request: ', mockUser);
        console.log('Response:', result);

        expect(result).toEqual({ accessToken: fakeAccess, refreshToken: fakeRefresh });
        expect(tokenUtils.generateAccessToken).toHaveBeenCalledWith(mockUser.id);
        expect(tokenUtils.generateRefreshToken).toHaveBeenCalledWith(mockUser.id);
    });
});

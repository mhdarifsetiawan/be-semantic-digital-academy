// src/services/authService.ts
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import ms from 'ms';

import { pool } from '../db/pools';
import { ApiError } from '../utils/ApiError';
import logger from '../utils/logger';
import { generateAccessToken, generateRefreshToken } from '../utils/token';

const JWT_SECRET = process.env.JWT_SECRET!;

interface RefreshPayload {
    type: 'refresh';
    userId: string;
}

export async function loginUser(email: string, password: string) {
    logger.info('Service: Fetching user data from DB...');
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
        logger.info('Service: 401 - Invalid email or password');
        throw new ApiError('Invalid email or password', 401);
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
        logger.info('Service: 401 - Invalid email or password');
        throw new ApiError('Invalid email or password', 401);
    }

    const accessToken = generateAccessToken(user.id);
    const refreshToken = await generateRefreshToken(user.id);

    const refreshExpiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN ?? '7d';
    const durationMs = ms(refreshExpiresIn) as number;

    logger.info('Service: Insert refresh token into DB');
    const expiresAt = new Date(Date.now() + durationMs);
    await pool.query('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)', [refreshToken, user.id, expiresAt]);

    return { accessToken, refreshToken };
}

export async function registerUser(email: string, password: string, name: string) {
    const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (rows.length > 0) throw new ApiError('Email already exists', 400);

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query('INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name', [
        email,
        hashedPassword,
        name,
    ]);

    return result.rows[0];
}

export async function removeRefreshToken(token: string) {
    await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [token]);
}

export async function validateRefreshTokenAndGenerateAccess(token: string): Promise<string> {
    if (!token) throw new ApiError('No refresh token provided', 401);

    let decoded: RefreshPayload;
    try {
        decoded = jwt.verify(token, JWT_SECRET) as RefreshPayload;
    } catch {
        throw new ApiError('Invalid or expired token', 403);
    }

    if (decoded.type !== 'refresh') {
        throw new ApiError('Invalid token type', 400);
    }

    const { rows } = await pool.query('SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()', [token]);

    if (rows.length === 0) {
        throw new ApiError('Refresh token not found or expired', 401);
    }

    return generateAccessToken(decoded.userId);
}

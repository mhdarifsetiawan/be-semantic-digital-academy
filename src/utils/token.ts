import jwt from 'jsonwebtoken';

if (!process.env.JWT_SECRET) {
    throw new Error('JWT secret environment variables are not set');
}

export const generateAccessToken = (userId: string): string => {
    console.info('ACCESS_TOKEN_EXPIRES_IN: ', process.env.ACCESS_TOKEN_EXPIRES_IN);
    return jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN ?? '15m' });
};

export const generateRefreshToken = (userId: string): string => {
    console.info('REFRESH_TOKEN_EXPIRES_IN: ', process.env.REFRESH_TOKEN_EXPIRES_IN);
    return jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN ?? '7d' });
};

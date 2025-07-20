import jwt, { SignOptions } from 'jsonwebtoken';

if (!process.env.JWT_SECRET) {
    throw new Error('JWT secret environment variables are not set');
}

const generateToken = (userId: string, type: 'access' | 'refresh', expiresIn: string): string => {
    const payload = { userId, type };
    // Cast expiresIn as any to bypass type checking issue
    const options: SignOptions = { expiresIn: expiresIn as any };
    return jwt.sign(payload, process.env.JWT_SECRET!, options);
};

export const generateAccessToken = (userId: string): string => {
    const expiresIn: string = process.env.ACCESS_TOKEN_EXPIRES_IN ?? '15m';
    console.info('generateAccessToken ACCESS_TOKEN_EXPIRES_IN: ', expiresIn);
    return generateToken(userId, 'access', expiresIn);
};

export const generateRefreshToken = (userId: string): string => {
    const expiresIn: string = process.env.REFRESH_TOKEN_EXPIRES_IN ?? '7d';
    console.info('REFRESH_TOKEN_EXPIRES_IN: ', expiresIn);
    return generateToken(userId, 'refresh', expiresIn);
};

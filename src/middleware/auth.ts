// src/middleware/auth.ts
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET as string;

export interface AuthRequest extends Request {
    userId?: string;
}

export function authenticateToken(req: AuthRequest, res: Response, next: NextFunction) {
    const token = req.cookies.accessToken;

    if (!token) return res.status(401).json({ message: 'No access token provided', rc: '01' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; exp: number };
        const currentTime = Math.floor(Date.now() / 1000);

        if (decoded.exp < currentTime) {
            return res.status(403).json({ message: 'Access token expired', rc: '01' });
        }

        req.userId = decoded.userId;
        next();
    } catch (err: any) {
        console.log(err.name)
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Access token expired', rc: '01' });
        }

        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid access token', rc: '01' });
        }

        return res.status(401).json({ message: 'Authentication failed', rc: '01' });
    }
}

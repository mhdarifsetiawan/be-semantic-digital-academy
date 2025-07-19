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
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };

        req.userId = decoded.userId;
        next();
    } catch (err) {
        return res.status(403).json({ message: 'Invalid or expired access token', rc: '01' });
    }
}

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { AuthRequest } from '../types/index.js';

export const protect = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        // 1) Get token from header
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            return res.status(401).json({
                message: 'You are not logged in. Please log in to get access.'
            });
        }

        const token = authHeader.split(' ')[1];

        // 2) Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;

        // 3) Check if user still exists
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({
                message: 'The user belonging to this token no longer exists.'
            });
        }

        // Grant access to protected route
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({
            message: 'Invalid token. Please log in again.'
        });
    }
};

export const restrictTo = (...roles: string[]) => {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
        if (!req.user) {
            return res.status(401).json({
                message: 'You are not logged in. Please log in to get access.'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                message: 'You do not have permission to perform this action'
            });
        }

        next();
    };
}; 
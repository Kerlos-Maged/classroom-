import { Document } from 'mongoose';

export interface OTPAttempt extends Document {
    user: Document['_id'];
    attempts: number;
    lastAttempt: Date;
    isBlocked: boolean;
    blockExpires?: Date;
    createdAt: Date;
    updatedAt: Date;
}

export interface User extends Document {
    email: string;
    password: string;
    fullName: string;
    role: 'student' | 'teacher' | 'admin';
    isVerified: boolean;
    isActive: boolean;
    passwordResetToken?: string;
    passwordResetExpires?: Date;
    otpAttempts?: OTPAttempt['_id'];
    comparePassword(candidatePassword: string): Promise<boolean>;
    createdAt: Date;
    updatedAt: Date;
}

export interface ErrorResponse extends Error {
    status?: number;
    code?: number;
    keyValue?: any;
    errors?: any;
}

export interface AuthRequest extends Request {
    user?: User;
}

export interface TokenPayload {
    id: string;
    role: string;
    iat: number;
    exp: number;
} 
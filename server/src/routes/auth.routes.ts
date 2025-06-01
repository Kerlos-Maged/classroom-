import express from 'express';
import { body } from 'express-validator';
import { validateRequest } from '../middleware/validateRequest';
import { protect, restrictTo } from '../middleware/auth';
import {
    register,
    login,
    logout,
    forgotPassword,
    resetPassword,
    verifyOTP,
    resendOTP,
} from '../controllers/auth.controller';

const router = express.Router();

// Public routes
router.post(
    '/register',
    [
        body('email').isEmail().withMessage('Please provide a valid email'),
        body('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long'),
        body('fullName').notEmpty().withMessage('Full name is required')
    ],
    validateRequest,
    register
);

router.post(
    '/login',
    [
        body('email').isEmail().withMessage('Please provide a valid email'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    validateRequest,
    login
);

router.post('/logout', logout);

router.post(
    '/forgot-password',
    [
        body('email').isEmail().withMessage('Please provide a valid email')
    ],
    validateRequest,
    forgotPassword
);

router.patch(
    '/reset-password/:token',
    [
        body('password')
            .isLength({ min: 8 })
            .withMessage('Password must be at least 8 characters long')
    ],
    validateRequest,
    resetPassword
);

router.post(
    '/verify-otp',
    [
        body('email').isEmail().withMessage('Please provide a valid email'),
        body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
    ],
    validateRequest,
    verifyOTP
);

router.post(
    '/resend-otp',
    [
        body('email').isEmail().withMessage('Please provide a valid email')
    ],
    validateRequest,
    resendOTP
);

// Protected routes
router.use(protect);

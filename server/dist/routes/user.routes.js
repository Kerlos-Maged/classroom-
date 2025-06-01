import express from 'express';
import { body } from 'express-validator';
import { validateRequest } from '../middleware/validateRequest';
import { protect, restrictTo } from '../middleware/auth';
import { register, login, logout, getMe, updateMe, deleteMe, getAllUsers, getUser, updateUser, deleteUser, forgotPassword, resetPassword, verifyOTP, resendOTP } from '../controllers/user.controller';
const router = express.Router();
// Public routes
router.post('/register', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long'),
    body('fullName').notEmpty().withMessage('Full name is required'),
    validateRequest
], register);
router.post('/login', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required'),
    validateRequest
], login);
router.post('/logout', logout);
router.post('/forgot-password', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    validateRequest
], forgotPassword);
router.post('/reset-password', [
    body('token').notEmpty().withMessage('Token is required'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long'),
    validateRequest
], resetPassword);
router.post('/verify-otp', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('otp').notEmpty().withMessage('OTP is required'),
    validateRequest
], verifyOTP);
router.post('/resend-otp', [
    body('email').isEmail().withMessage('Please provide a valid email'),
    validateRequest
], resendOTP);
// Protect all routes after this middleware
router.use(protect);
// User routes
router.get('/me', getMe);
router.patch('/update-me', [
    body('email').optional().isEmail().withMessage('Please provide a valid email'),
    body('fullName').optional().notEmpty().withMessage('Full name cannot be empty')
], validateRequest, updateMe);
router.delete('/delete-me', deleteMe);
// Admin routes
router.use(restrictTo('admin'));
router.get('/', getAllUsers);
router.get('/:id', getUser);
router.patch('/:id', [
    body('email').optional().isEmail().withMessage('Please provide a valid email'),
    body('fullName').optional().notEmpty().withMessage('Full name cannot be empty'),
    body('role').optional().isIn(['student', 'teacher', 'admin']).withMessage('Invalid role')
], validateRequest, updateUser);
router.delete('/:id', deleteUser);
export default router;

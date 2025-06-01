import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User';
import OTPAttempt from '../models/OTPAttempt';
import { sendEmail } from '../utils/email';
import { generateOTP } from '../utils/otp';
import logger from '../config/logger';
const signToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};
const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    // Remove password from output
    user.password = undefined;
    res.status(statusCode).json({
        status: 'success',
        token,
        data: { user }
    });
};
export const register = async (req, res) => {
    try {
        const { email, password, fullName } = req.body;
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                message: 'User already exists with this email'
            });
        }
        // Create new user
        const user = await User.create({
            email,
            password,
            fullName,
            role: 'student' // Default role
        });
        // Generate and send OTP
        const otp = generateOTP();
        await OTPAttempt.create({
            user: user._id,
            attempts: 0
        });
        // Send verification email
        await sendEmail({
            email: user.email,
            subject: 'Verify your email',
            message: `Your verification code is: ${otp}`
        });
        createSendToken(user, 201, res);
    }
    catch (error) {
        logger.error('Registration error:', error);
        res.status(500).json({
            message: 'Error creating user'
        });
    }
};
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        // Check if user exists
        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            return res.status(401).json({
                message: 'Incorrect email or password'
            });
        }
        // Check if password is correct
        const isPasswordCorrect = await user.comparePassword(password);
        if (!isPasswordCorrect) {
            return res.status(401).json({
                message: 'Incorrect email or password'
            });
        }
        // Check if user is verified
        if (!user.isVerified) {
            return res.status(401).json({
                message: 'Please verify your email first'
            });
        }
        createSendToken(user, 200, res);
    }
    catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({
            message: 'Error logging in'
        });
    }
};
export const logout = (req, res) => {
    res.status(200).json({ status: 'success' });
};
export const getMe = async (req, res) => {
    try {
        const user = await User.findById(req.user?._id);
        res.status(200).json({
            status: 'success',
            data: { user }
        });
    }
    catch (error) {
        logger.error('Get me error:', error);
        res.status(500).json({
            message: 'Error fetching user data'
        });
    }
};
export const updateMe = async (req, res) => {
    try {
        // Filter out unwanted fields
        const filteredBody = {
            fullName: req.body.fullName,
            email: req.body.email
        };
        const user = await User.findByIdAndUpdate(req.user?._id, filteredBody, { new: true, runValidators: true });
        res.status(200).json({
            status: 'success',
            data: { user }
        });
    }
    catch (error) {
        logger.error('Update me error:', error);
        res.status(500).json({
            message: 'Error updating user data'
        });
    }
};
export const deleteMe = async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user?._id, { isActive: false });
        res.status(204).json({
            status: 'success',
            data: null
        });
    }
    catch (error) {
        logger.error('Delete me error:', error);
        res.status(500).json({
            message: 'Error deleting user'
        });
    }
};
export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json({
            status: 'success',
            results: users.length,
            data: { users }
        });
    }
    catch (error) {
        logger.error('Get all users error:', error);
        res.status(500).json({
            message: 'Error fetching users'
        });
    }
};
export const getUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({
                message: 'No user found with that ID'
            });
        }
        res.status(200).json({
            status: 'success',
            data: { user }
        });
    }
    catch (error) {
        logger.error('Get user error:', error);
        res.status(500).json({
            message: 'Error fetching user'
        });
    }
};
export const updateUser = async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!user) {
            return res.status(404).json({
                message: 'No user found with that ID'
            });
        }
        res.status(200).json({
            status: 'success',
            data: { user }
        });
    }
    catch (error) {
        logger.error('Update user error:', error);
        res.status(500).json({
            message: 'Error updating user'
        });
    }
};
export const deleteUser = async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({
                message: 'No user found with that ID'
            });
        }
        res.status(204).json({
            status: 'success',
            data: null
        });
    }
    catch (error) {
        logger.error('Delete user error:', error);
        res.status(500).json({
            message: 'Error deleting user'
        });
    }
};
export const forgotPassword = async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).json({
                message: 'There is no user with that email address'
            });
        }
        // Generate random reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.passwordResetToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');
        user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        await user.save();
        // Send reset email
        const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/reset-password/${resetToken}`;
        await sendEmail({
            email: user.email,
            subject: 'Your password reset token (valid for 10 minutes)',
            message: `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}`
        });
        res.status(200).json({
            status: 'success',
            message: 'Token sent to email'
        });
    }
    catch (error) {
        logger.error('Forgot password error:', error);
        res.status(500).json({
            message: 'Error sending reset token'
        });
    }
};
export const resetPassword = async (req, res) => {
    try {
        // Get user based on the token
        const hashedToken = crypto
            .createHash('sha256')
            .update(req.body.token)
            .digest('hex');
        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });
        if (!user) {
            return res.status(400).json({
                message: 'Token is invalid or has expired'
            });
        }
        // Update password
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();
        // Log the user in
        createSendToken(user, 200, res);
    }
    catch (error) {
        logger.error('Reset password error:', error);
        res.status(500).json({
            message: 'Error resetting password'
        });
    }
};
export const verifyOTP = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: 'No user found with that email'
            });
        }
        const otpAttempt = await OTPAttempt.findOne({ user: user._id });
        if (!otpAttempt) {
            return res.status(400).json({
                message: 'No OTP attempt found'
            });
        }
        if (otpAttempt.isBlocked) {
            if (otpAttempt.blockExpires && otpAttempt.blockExpires > new Date()) {
                return res.status(400).json({
                    message: 'Too many attempts. Please try again later'
                });
            }
            // Reset block if expired
            otpAttempt.isBlocked = false;
            otpAttempt.attempts = 0;
        }
        // Verify OTP
        if (otp !== otpAttempt.otp) {
            otpAttempt.attempts += 1;
            if (otpAttempt.attempts >= 3) {
                otpAttempt.isBlocked = true;
                otpAttempt.blockExpires = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
            }
            await otpAttempt.save();
            return res.status(400).json({
                message: 'Invalid OTP'
            });
        }
        // Mark user as verified
        user.isVerified = true;
        await user.save();
        // Clear OTP attempt
        await OTPAttempt.findByIdAndDelete(otpAttempt._id);
        res.status(200).json({
            status: 'success',
            message: 'Email verified successfully'
        });
    }
    catch (error) {
        logger.error('Verify OTP error:', error);
        res.status(500).json({
            message: 'Error verifying OTP'
        });
    }
};
export const resendOTP = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: 'No user found with that email'
            });
        }
        if (user.isVerified) {
            return res.status(400).json({
                message: 'User is already verified'
            });
        }
        // Generate new OTP
        const otp = generateOTP();
        const otpAttempt = await OTPAttempt.findOne({ user: user._id });
        if (otpAttempt) {
            if (otpAttempt.isBlocked && otpAttempt.blockExpires && otpAttempt.blockExpires > new Date()) {
                return res.status(400).json({
                    message: 'Too many attempts. Please try again later'
                });
            }
            // Reset attempts
            otpAttempt.attempts = 0;
            otpAttempt.isBlocked = false;
            otpAttempt.blockExpires = undefined;
            otpAttempt.otp = otp;
            otpAttempt.lastAttempt = new Date();
            await otpAttempt.save();
        }
        else {
            await OTPAttempt.create({
                user: user._id,
                otp,
                attempts: 0
            });
        }
        // Send new OTP
        await sendEmail({
            email: user.email,
            subject: 'Your new verification code',
            message: `Your new verification code is: ${otp}`
        });
        res.status(200).json({
            status: 'success',
            message: 'New OTP sent successfully'
        });
    }
    catch (error) {
        logger.error('Resend OTP error:', error);
        res.status(500).json({
            message: 'Error sending new OTP'
        });
    }
};

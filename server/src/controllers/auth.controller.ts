import { Request, Response } from 'express';
import jwt, { SignOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { AuthRequest } from '../types';
import User from '../models/User';
import OTPAttempt from '../models/OTPAttempt';
import { sendEmail } from '../utils/email';
import { generateOTP } from '../utils/otp';
import logger from '../config/logger';

const signToken = (id: string): string => {
    if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET is not defined');
    }

    const options: SignOptions = {
        expiresIn: 60 * 60 * 24 // 1 day in seconds
    };

    if (process.env.JWT_EXPIRES_IN) {
        const expiresIn = parseInt(process.env.JWT_EXPIRES_IN, 10);
        if (!isNaN(expiresIn)) {
            options.expiresIn = expiresIn;
        }
    }

    return jwt.sign(
        { id },
        process.env.JWT_SECRET,
        options
    );
};

const createSendToken = (user: any, statusCode: number, res: Response) => {
    const token = signToken(user._id);

    // Remove password from output
    user.password = undefined;

    res.status(statusCode).json({
        status: 'success',
        token,
        data: { user }
    });
};

export const register = async (req: Request, res: Response) => {
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
            otp,
            attempts: 0
        });

        // Send verification email
        await sendEmail({
            email: user.email,
            subject: 'Verify your email',
            message: `Your verification code is: ${otp}`
        });

        createSendToken(user, 201, res);
    } catch (error) {
        logger.error('Registration error:', error);
        res.status(500).json({
            message: 'Error creating user'
        });
    }
};

export const login = async (req: Request, res: Response) => {
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
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({
            message: 'Error logging in'
        });
    }
};

export const logout = (req: Request, res: Response) => {
    res.status(200).json({ status: 'success' });
};

export const forgotPassword = async (req: Request, res: Response) => {
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
        const resetURL = `${req.protocol}://${req.get('host')}/api/v1/auth/reset-password/${resetToken}`;
        await sendEmail({
            email: user.email,
            subject: 'Your password reset token (valid for 10 minutes)',
            message: `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}`
        });

        res.status(200).json({
            status: 'success',
            message: 'Token sent to email'
        });
    } catch (error) {
        logger.error('Forgot password error:', error);
        res.status(500).json({
            message: 'Error sending reset token'
        });
    }
};

export const resetPassword = async (req: Request, res: Response) => {
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
    } catch (error) {
        logger.error('Reset password error:', error);
        res.status(500).json({
            message: 'Error resetting password'
        });
    }
};

export const verifyOTP = async (req: Request, res: Response) => {
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
    } catch (error) {
        logger.error('Verify OTP error:', error);
        res.status(500).json({
            message: 'Error verifying OTP'
        });
    }
};

export const resendOTP = async (req: Request, res: Response) => {
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
        } else {
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
    } catch (error) {
        logger.error('Resend OTP error:', error);
        res.status(500).json({
            message: 'Error sending new OTP'
        });
    }
}; 
import { Request, Response } from 'express';
import jwt, { SignOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { AuthRequest } from '../types/index.js';
import User from '../models/User.js';
// import OTPAttempt from '../models/OTPAttempt.js';
// import { sendEmail } from '../utils/email.js';
// import { generateOTP } from '../utils/otp.js';
import logger from '../config/logger.js';

const signToken = (id: string): string => {
    if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET is not defined');
    }

    // const options: SignOptions = {
    //     expiresIn: 60 * 60 * 24 // 1 day in seconds
    // };

    // if (process.env.JWT_EXPIRES_IN) {
    //     const expiresIn = parseInt(process.env.JWT_EXPIRES_IN, 10);
    //     if (!isNaN(expiresIn)) {
    //         options.expiresIn = expiresIn;
    //     }
    // }

    return jwt.sign(
        { id },
        process.env.JWT_SECRET,
    );
};

const createSendToken = (user: any, statusCode: number, res: Response) => {
    const token = signToken(user._id.toString());

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
        const { email, password, fullName, role } = req.body;

        // Validate required fields
        if (!email || !password || !fullName) {
            return res.status(400).json({
                message: 'Please provide email, password, and fullName'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            // If user exists, try to log them in instead
            const isPasswordCorrect = await existingUser.comparePassword(password);
            if (isPasswordCorrect) {
                // Generate token for existing user
                const token = signToken(existingUser._id);
                return res.status(200).json({
                    status: 'success',
                    message: 'User already exists. Logged in successfully.',
                    token,
                    data: {
                        user: {
                            _id: existingUser._id,
                            email: existingUser.email,
                            fullName: existingUser.fullName,
                            role: existingUser.role,
                            isVerified: existingUser.isVerified
                        }
                    }
                });
            } else {
                return res.status(400).json({
                    message: 'User already exists with this email. Please use a different email or try logging in.'
                });
            }
        }

        // Validate role if provided
        if (role && !['student', 'teacher', 'admin'].includes(role)) {
            return res.status(400).json({
                message: 'Invalid role. Must be student, teacher, or admin'
            });
        }

        // Create new user
        const user = await User.create({
            email,
            password,
            fullName,
            role: role || 'student',
            isVerified: true // Set to true since we're skipping OTP
        });

        // Send token response
        console.log(user._id);
        const token = signToken(user._id.toString());
        
        res.status(201).json({
            status: 'success',
            token,
            data: {
                user: {
                    _id: user._id,
                    email: user.email,
                    fullName: user.fullName,
                    role: user.role,
                    isVerified: user.isVerified
                }
            }
        });

    } catch (error: any) {
        logger.error('Registration error:', error);
        res.status(500).json({
            message: 'Error creating user',
            error: error.message
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

        // Email sending disabled
        /*
        // Send reset email
        const resetURL = `${req.protocol}://${req.get('host')}/api/v1/auth/reset-password/${resetToken}`;
        await sendEmail({
            email: user.email,
            subject: 'Your password reset token (valid for 10 minutes)',
            message: `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}`
        });
        */

        res.status(200).json({
            status: 'success',
            message: 'Token sent to email',
            resetToken // Sending token in response for testing
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

        // OTP verification disabled
        /*
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
        */

        // Mark user as verified
        user.isVerified = true;
        await user.save();

        // Clear OTP attempt
        // await OTPAttempt.findByIdAndDelete(otpAttempt._id);

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

        // OTP resend disabled
        /*
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
        */

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
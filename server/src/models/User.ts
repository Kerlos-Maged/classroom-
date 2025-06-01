import mongoose, { Document, Schema } from 'mongoose';
import bcrypt from 'bcryptjs';
import { User, OTPAttempt } from '../types';

export interface IUser extends Document {
    email: string;
    password: string;
    fullName: string;
    role: 'student' | 'teacher' | 'admin';
    isVerified: boolean;
    isActive: boolean;
    passwordResetToken?: string;
    passwordResetExpires?: Date;
    otpAttempts: number;
    comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<User>({
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: 8,
        select: false
    },
    fullName: {
        type: String,
        required: [true, 'Full name is required'],
        trim: true
    },
    role: {
        type: String,
        enum: ['student', 'teacher', 'admin'],
        default: 'student'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    },
    passwordResetToken: {
        type: String
    },
    passwordResetExpires: {
        type: Date
    },
    otpAttempts: {
        type: Schema.Types.ObjectId,
        ref: 'OTPAttempt'
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error: any) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw error;
    }
};

const User = mongoose.model<User>('User', userSchema);

export default User; 
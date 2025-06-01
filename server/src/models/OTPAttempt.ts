import mongoose, { Document, Schema } from 'mongoose';
import { OTPAttempt } from '../types';

const otpAttemptSchema = new Schema<OTPAttempt>({
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    attempts: {
        type: Number,
        default: 0
    },
    lastAttempt: {
        type: Date,
        default: Date.now
    },
    isBlocked: {
        type: Boolean,
        default: false
    },
    blockExpires: {
        type: Date
    }
}, {
    timestamps: true
});

// Index for faster queries
otpAttemptSchema.index({ user: 1 });
otpAttemptSchema.index({ blockExpires: 1 }, { expireAfterSeconds: 0 });

const OTPAttempt = mongoose.model<OTPAttempt>('OTPAttempt', otpAttemptSchema);

export default OTPAttempt; 
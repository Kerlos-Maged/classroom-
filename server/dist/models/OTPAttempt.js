import mongoose from 'mongoose';
const otpAttemptSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    otp: {
        type: String,
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
otpAttemptSchema.index({ lastAttempt: 1 });
const OTPAttempt = mongoose.model('OTPAttempt', otpAttemptSchema);
export default OTPAttempt;

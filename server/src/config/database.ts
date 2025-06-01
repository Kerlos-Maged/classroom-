import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const connectDB = async (): Promise<void> => {
    try {
        const mongoURI: string = process.env.MONGODB_URI || 'mongodb://localhost:27017/mern-app';
        await mongoose.connect(mongoURI);
        console.log('MongoDB is Connected successfully');
    } catch (err) {
        console.error('MongoDB Connection Error:', err);
        process.exit(1);
    }
};

export default connectDB; 
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import compression from 'compression';
import hpp from 'hpp';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import connectDB from './config/database.js';
import logger from './config/logger.js';
// Load environment variables
dotenv.config();
// Create Express app
const app = express();
// Security Middleware
app.use(helmet()); // Set security HTTP headers
app.use(hpp()); // Prevent HTTP Parameter Pollution
// Middleware
app.use(cors());
app.use(cookieParser());
app.use(compression()); // Compress all responses
app.use(morgan('dev')); // HTTP request logger
// Basic route
app.get('/', (req, res) => {
    res.json({ message: 'Classroom API' });
});
app.use((err, req, res, next) => {
    console.error(err.stack);
    logger.error(err.stack);
    res.status(err.status || 500).json({
        message: err.message || 'Something went wrong!'
    });
});
// Start server
const PORT = parseInt(process.env.PORT || '5000', 10);
const startServer = async () => {
    try {
        await connectDB();
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
            logger.info(`Server started on port ${PORT}`);
        });
    }
    catch (err) {
        console.error('Failed to start server:', err);
        logger.error('Failed to start server:', err);
        process.exit(1);
    }
};
// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    logger.error('Uncaught Exception:', err);
    process.exit(1);
});
// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
    logger.error('Unhandled Rejection:', err);
    process.exit(1);
});
startServer();

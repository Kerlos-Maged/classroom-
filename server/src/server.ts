import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import connectDB from './config/database.js';
import logger from './config/logger.js';
import routes from './routes/index.js';

const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(cookieParser()); // Parse cookies
app.use(morgan('dev')); // HTTP request logging

// Mount routes
app.use('/api/v1', routes);

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    logger.error(err.stack);
    res.status(err.status || 500).json({
        status: 'error',
        message: err.message || 'Internal server error'
    });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    logger.error('UNCAUGHT EXCEPTION! Shutting down...');
    logger.error(err.name, err.message);
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err: any) => {
    logger.error('UNHANDLED REJECTION! Shutting down...');
    logger.error(err.name, err.message);
    process.exit(1);
}); 
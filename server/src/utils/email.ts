import nodemailer from 'nodemailer';
import logger from '../config/logger';

interface EmailOptions {
    email: string;
    subject: string;
    message: string;
}

export const sendEmail = async (options: EmailOptions) => {
    try {
        // Create transporter
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: parseInt(process.env.EMAIL_PORT || '587'),
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        // Define email options
        const mailOptions = {
            from: `Classroom App <${process.env.EMAIL_FROM}>`,
            to: options.email,
            subject: options.subject,
            text: options.message
        };

        // Send email
        await transporter.sendMail(mailOptions);
        logger.info(`Email sent to ${options.email}`);
    } catch (error) {
        logger.error('Error sending email:', error);
        throw new Error('Error sending email');
    }
}; 
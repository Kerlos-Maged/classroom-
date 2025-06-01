import fs from 'fs';
import path from 'path';
import logger from '../config/logger.js';

export const saveQRImage = async (base64Data: string, userId: string): Promise<string> => {
    try {
        // Create images directory if it doesn't exist
        const imagesDir = path.join(__dirname, '..', '..', '..', 'images');
        logger.info('Attempting to save QR image to directory:', imagesDir);
        
        if (!fs.existsSync(imagesDir)) {
            logger.info('Creating images directory...');
            fs.mkdirSync(imagesDir, { recursive: true });
            logger.info('Images directory created successfully');
        }

        // Remove the data URL prefix if present
        const base64Image = base64Data.replace(/^data:image\/png;base64,/, '');
        logger.info('Base64 data processed, length:', base64Image.length);
        
        // Convert base64 to buffer
        const imageBuffer = Buffer.from(base64Image, 'base64');
        logger.info('Buffer created, size:', imageBuffer.length);
        
        // Create filename with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `qr_${userId}_${timestamp}.png`;
        const filePath = path.join(imagesDir, filename);
        logger.info('Saving file to:', filePath);

        // Save the file
        fs.writeFileSync(filePath, imageBuffer);
        logger.info('File saved successfully');
        
        return filePath;
    } catch (error: any) {
        logger.error('Error saving QR image:', error);
        throw new Error(`Failed to save QR image: ${error.message}`);
    }
}; 
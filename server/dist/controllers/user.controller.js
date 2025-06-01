import User from '../models/User.js';
import { generateUserExcel } from '../utils/excel.js';
import logger from '../config/logger.js';
import path from 'path';
import fs from 'fs';
export const generateUserExcelFile = async (req, res) => {
    try {
        // Get all users
        const users = await User.find().select('-password');
        // Generate Excel workbook
        const workbook = await generateUserExcel(users);
        // Create excel_files directory in the root of the project
        const uploadsDir = path.join(__dirname, '..', '..', '..', 'excel_files');
        console.log('Creating directory at:', uploadsDir);
        try {
            if (!fs.existsSync(uploadsDir)) {
                fs.mkdirSync(uploadsDir, { recursive: true });
                console.log('Directory created successfully');
            }
        }
        catch (dirError) {
            console.error('Error creating directory:', dirError);
            throw new Error(`Failed to create directory: ${dirError.message}`);
        }
        // Save file locally with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filePath = path.join(uploadsDir, `users_${timestamp}.xlsx`);
        console.log('Saving file to:', filePath);
        try {
            await workbook.xlsx.writeFile(filePath);
            console.log('File saved successfully');
        }
        catch (writeError) {
            console.error('Error writing file:', writeError);
            throw new Error(`Failed to write file: ${writeError.message}`);
        }
        res.status(200).json({
            status: 'success',
            message: 'Excel file generated successfully',
            filePath: filePath
        });
    }
    catch (error) {
        logger.error('Error generating user Excel file:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error generating user Excel file',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};

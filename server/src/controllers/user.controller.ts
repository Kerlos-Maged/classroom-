import { Request, Response } from 'express';
import User from '../models/User.js';
import { generateUserExcel } from '../utils/excel.js';
import logger from '../config/logger.js';

export const generateUserExcelFile = async (req: Request, res: Response) => {
    try {
        // Get all users
        const users = await User.find().select('-password');
        
        // Generate Excel workbook
        const workbook = await generateUserExcel(users);

        // Set response headers
        res.setHeader(
            'Content-Type',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );
        res.setHeader(
            'Content-Disposition',
            'attachment; filename=users.xlsx'
        );

        // Write to response
        await workbook.xlsx.write(res);
        res.end();

    } catch (error) {
        logger.error('Error generating user Excel file:', error);
        res.status(500).json({
            status: 'error',
            message: 'Error generating user Excel file'
        });
    }
}; 
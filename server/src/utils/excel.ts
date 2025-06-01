import ExcelJS from 'exceljs';
import { User } from '../types/index.js';
import logger from '../config/logger.js';

export const generateUserExcel = async (users: User[]) => {
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Users');

    // Set column headers
    worksheet.columns = [
        { header: 'ID', key: 'id', width: 10 },
        { header: 'Full Name', key: 'fullName', width: 30 },
        { header: 'Email', key: 'email', width: 30 },
        { header: 'Role', key: 'role', width: 15 },
        { header: 'Authority', key: 'authority', width: 20 }
    ];

    // Add rows with user data
    for (const user of users) {
        try {
            logger.info(`Processing user: ${user._id}`);
            
            worksheet.addRow({
                id: user._id.toString(),
                fullName: user.fullName,
                email: user.email,
                role: user.role,
                authority: user.role === 'admin' ? 'full' : 'limited'
            });
        } catch (error) {
            logger.error(`Error processing user ${user._id}:`, error);
        }
    }

    // Style the header row
    worksheet.getRow(1).font = { bold: true };
    worksheet.getRow(1).alignment = { vertical: 'middle', horizontal: 'center' };

    return workbook;
}; 
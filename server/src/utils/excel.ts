import ExcelJS from 'exceljs';
import QRCode from 'qrcode';
import { User } from '../types/index.js';

export const generateUserExcel = async (users: User[]) => {
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Users');

    // Set column headers
    worksheet.columns = [
        { header: 'ID', key: 'id', width: 10 },
        { header: 'Full Name', key: 'fullName', width: 30 },
        { header: 'Email', key: 'email', width: 30 },
        { header: 'Role', key: 'role', width: 15 },
        { header: 'QR Code', key: 'qrCode', width: 20 }
    ];

    // Add rows with user data and QR codes
    for (const user of users) {
        // Generate QR code with user data
        const qrData = JSON.stringify({
            id: user._id,
            email: user.email,
            role: user.role
        });
        
        const qrCode = await QRCode.toDataURL(qrData);

        worksheet.addRow({
            id: user._id.toString(),
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            qrCode: { text: 'QR Code', hyperlink: qrCode }
        });
    }

    // Style the header row
    worksheet.getRow(1).font = { bold: true };
    worksheet.getRow(1).alignment = { vertical: 'middle', horizontal: 'center' };

    return workbook;
}; 
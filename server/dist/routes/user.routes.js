import express from 'express';
import { protect, restrictTo } from '../middleware/auth.js';
import { generateUserExcelFile } from '../controllers/user.controller.js';
const router = express.Router();
// Generate Excel file with user data and QR codes (admin only)
router.get('/excel', protect, restrictTo('admin'), generateUserExcelFile);
export default router;

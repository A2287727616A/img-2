const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// POST /api/auth/register
router.post('/register', authController.register);

// GET /api/auth/verify-email?token=<token>
router.get('/verify-email', authController.verifyEmail);

// POST /api/auth/login
router.post('/login', authController.login);

// POST /api/auth/request-password-reset
router.post('/request-password-reset', authController.requestPasswordReset);

// POST /api/auth/reset-password
router.post('/reset-password', authController.resetPassword);

// Add other auth routes here etc.

module.exports = router;

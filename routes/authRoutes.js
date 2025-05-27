const express = require('express');
const authController = require('../controllers/authController');
const { verifyTurnstile } = require('../middlewares/turnstileMiddleware');

const router = express.Router();

// POST /api/auth/register
router.post('/register', verifyTurnstile, authController.register);

// GET /api/auth/verify-email?token=<token> - No Turnstile for email link verification
router.get('/verify-email', authController.verifyEmail);

// POST /api/auth/login
router.post('/login', verifyTurnstile, authController.login);

// POST /api/auth/request-password-reset
router.post('/request-password-reset', verifyTurnstile, authController.requestPasswordReset);

// POST /api/auth/reset-password - No Turnstile for password reset confirmation (token based)
router.post('/reset-password', authController.resetPassword);

// POST /api/auth/verify-2fa (for login flow) - No Turnstile, follows successful password & Turnstile on /login
router.post('/verify-2fa', authController.verify2FA);

// Add other auth routes here etc.

module.exports = router;

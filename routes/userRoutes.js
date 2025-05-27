const express = require('express');
const userController = require('../controllers/userController');
const { isAuthenticated } = require('../middlewares/authMiddleware');

const router = express.Router();

// All routes below are protected by the isAuthenticated middleware
router.use(isAuthenticated);

// Route for requesting OTP to current email for email change verification
// POST /api/user/request-email-change-otp
router.post('/request-email-change-otp', userController.requestEmailChangeOTP);

// Route for initiating email change (after OTP to old email is verified by user)
// POST /api/user/request-email-change
router.post('/request-email-change', userController.requestEmailChange);

// Route for verifying the new email address (link sent to new email)
// This route is GET as it's typically a link clicked from an email.
// It does not strictly need isAuthenticated if the token is unique and time-limited,
// but for consistency with other user-related actions and potential session usage,
// it's placed here. If it were public, it'd be in authRoutes.
// For this task, we'll assume it can be called without an active session token,
// as the email change token itself provides verification.
// However, the task implies it's part of userRoutes, so we'll keep it here.
// The controller logic itself does not depend on req.user for this specific route.
// If it needs to be public, it should be moved out of router.use(isAuthenticated).
// Given the task structure, let's keep it as is and assume the frontend handles any session.
// For a pure API, this might be better as a public route not under /api/user or not using isAuthenticated.
// Let's remove isAuthenticated for this specific route.

const tempRouter = express.Router(); // Temporary router for public routes
tempRouter.get('/verify-new-email', userController.verifyNewEmail);
tempRouter.get('/confirm-delete-account', userController.confirmAccountDeletion);


// Merge the temporary router for the public route before the isAuthenticated middleware
const mainRouter = express.Router();
mainRouter.use('/', tempRouter); // Add the public routes
mainRouter.use(isAuthenticated); // Protect subsequent routes
mainRouter.post('/request-email-change-otp', userController.requestEmailChangeOTP);
mainRouter.post('/request-email-change', userController.requestEmailChange);

// Account Deletion
mainRouter.post('/request-account-deletion', userController.requestAccountDeletion);
mainRouter.post('/cancel-account-deletion', userController.cancelAccountDeletion);


// Placeholder for other user-specific routes like:
// router.get('/profile', userController.getProfile);
// router.put('/profile', userController.updateProfile);

module.exports = mainRouter; // Export the main router

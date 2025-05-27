const express = require('express');
const multer = require('multer');
const imageController = require('../controllers/imageController');
const { verifyTurnstile } = require('../middlewares/turnstileMiddleware');
const { optionalAuth } = require('../middlewares/authMiddleware');
const logger = require('../config/logger'); // For logging Multer errors if needed

const router = express.Router();

// Multer configuration
const maxUploadLimit = 128 * 1024 * 1024; // Max possible limit: 128MB
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { fileSize: maxUploadLimit },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      // Pass an error object to cb for Multer to catch
      // This error can be caught by a custom Multer error handler or a global one
      const err = new Error('Invalid file type. Only JPEG, PNG, GIF, WebP allowed by Multer fileFilter.');
      err.code = 'INVALID_FILE_TYPE'; // Custom error code for easier identification
      // req.multerError = 'INVALID_FILE_TYPE'; // Alternative way to pass error info
      cb(err, false);
    }
  }
});

// POST /api/images/upload
router.post(
  '/upload',
  optionalAuth,      // 1. Check for optional authentication
  verifyTurnstile,   // 2. Verify Turnstile CAPTCHA
  (req, res, next) => { // 3. Multer middleware with custom error handling
    upload.single('image')(req, res, (err) => {
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          logger.warn('Multer: File too large.', { error: err.message, ip: req.ip, userId: req.user ? req.user.id : null });
          return res.status(413).json({ message: `File too large. Max size is ${maxUploadLimit / (1024*1024)}MB.` });
        }
        if (err.code === 'INVALID_FILE_TYPE') {
           logger.warn('Multer: Invalid file type by fileFilter.', { error: err.message, ip: req.ip, userId: req.user ? req.user.id : null });
           // Set a flag for the controller to know this specific error occurred
           req.multerError = 'INVALID_FILE_TYPE'; 
           //return res.status(400).json({ message: err.message }); // Or let controller handle
        }
        // For other Multer errors or unexpected errors
        logger.error('Multer: Unexpected error during upload.single.', { error: err.message, stack: err.stack, ip: req.ip, userId: req.user ? req.user.id : null });
        // return res.status(500).json({ message: 'Error processing file upload.' }); // Or let controller handle
      }
      // If no error, or if we want controller to handle specific flags (like INVALID_FILE_TYPE)
      next(); 
    });
  },
  imageController.uploadImage // 4. Finally, the controller
);

module.exports = router;

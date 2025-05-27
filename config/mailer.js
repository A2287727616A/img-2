const nodemailer = require('nodemailer');
const logger = require('./logger'); // Assuming logger is in config/logger.js
const dotenv = require('dotenv');

dotenv.config();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  debug: process.env.NODE_ENV === 'development', // Enable debug output in development
  logger: process.env.NODE_ENV === 'development' ? logger : false, // Use winston logger for debug output in dev
});

transporter.verify((error, success) => {
  if (error) {
    logger.error('Mailer verification error:', {
      message: error.message,
      stack: error.stack,
      code: error.code,
      command: error.command
    });
  } else {
    logger.info('Mailer is configured and ready to send emails.');
  }
});

module.exports = transporter;

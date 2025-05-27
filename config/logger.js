const winston = require('winston');
const { combine, timestamp, printf, colorize, json, errors } = winston.format;
require('winston-daily-rotate-file');

const logDir = 'logs';

// Define log formats
const consoleFormat = printf(({ level, message, timestamp, stack }) => {
  return `${timestamp} ${level}: ${stack || message}`;
});

const fileFormat = combine(
  timestamp(),
  errors({ stack: true }), // Log stack trace for errors
  json()
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: fileFormat,
  transports: [
    // Console transport (for development)
    new winston.transports.Console({
      format: combine(
        colorize(),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        consoleFormat
      ),
      level: 'debug', // Log debug and above to console
    }),
    // File transport for all application logs
    new winston.transports.DailyRotateFile({
      filename: `${logDir}/app-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m', // Max size of each file
      maxFiles: '14d', // Keep logs for 14 days
      format: fileFormat,
      level: 'info', // Log info and above to app.log
    }),
    // File transport for error logs
    new winston.transports.DailyRotateFile({
      filename: `${logDir}/error-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
      format: fileFormat,
      level: 'error', // Log only errors to error.log
    }),
  ],
  exceptionHandlers: [
    new winston.transports.DailyRotateFile({
      filename: `${logDir}/exceptions-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
      format: fileFormat,
    }),
    new winston.transports.Console({ // Also log exceptions to console
      format: combine(
        colorize(),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        consoleFormat
      ),
    })
  ],
  rejectionHandlers: [ // Handle unhandled promise rejections
    new winston.transports.DailyRotateFile({
      filename: `${logDir}/rejections-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
      format: fileFormat,
    }),
    new winston.transports.Console({
       format: combine(
        colorize(),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        consoleFormat
      ),
    })
  ],
  exitOnError: false, // Do not exit on handled exceptions
});

module.exports = logger;

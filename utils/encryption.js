const crypto = require('crypto');
const logger = require('../config/logger'); // Assuming logger is in config/logger.js
const dotenv = require('dotenv');

dotenv.config();

const ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = Buffer.from(process.env.TWO_FACTOR_ENCRYPTION_KEY, 'hex'); // Key must be 32 bytes (64 hex characters)
const IV_LENGTH = 16; // For AES-GCM, IV is typically 12 or 16 bytes. Using 16 for consistency.
const AUTH_TAG_LENGTH = 16; // GCM auth tag length

if (ENCRYPTION_KEY.length !== 32) {
  const errMsg = 'TWO_FACTOR_ENCRYPTION_KEY must be 32 bytes (64 hex characters). Current length: ' + ENCRYPTION_KEY.length + ' bytes.';
  logger.error(errMsg);
  // Application should not start if key is invalid.
  // This check helps during development. In production, ensure key is correctly set.
  throw new Error(errMsg);
}

/**
 * Encrypts text using AES-256-GCM.
 * @param {string} text The text to encrypt.
 * @returns {string|null} Encrypted string (iv:encrypted:authTag) in hex, or null on error.
 */
function encrypt(text) {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
  } catch (error) {
    logger.error('Encryption failed:', { message: error.message, stack: error.stack });
    return null;
  }
}

/**
 * Decrypts text encrypted with AES-256-GCM.
 * @param {string} encryptedText The encrypted string (iv:encrypted:authTag in hex).
 * @returns {string|null} Decrypted text, or null on error or if format is invalid.
 */
function decrypt(encryptedText) {
  try {
    if (!encryptedText || typeof encryptedText !== 'string') {
        logger.warn('Decrypt called with invalid input type.');
        return null;
    }
    const parts = encryptedText.split(':');
    if (parts.length !== 3) {
      logger.error('Decryption failed: Invalid encrypted text format.');
      return null;
    }

    const iv = Buffer.from(parts[0], 'hex');
    const encryptedData = parts[1];
    const authTag = Buffer.from(parts[2], 'hex');

    if (iv.length !== IV_LENGTH) {
        logger.error(`Decryption failed: IV length is incorrect. Expected ${IV_LENGTH}, got ${iv.length}`);
        return null;
    }
     if (authTag.length !== AUTH_TAG_LENGTH) {
        logger.error(`Decryption failed: AuthTag length is incorrect. Expected ${AUTH_TAG_LENGTH}, got ${authTag.length}`);
        return null;
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    logger.error('Decryption failed:', { message: error.message, stack: error.stack });
    // Common errors: "Unsupported state or unable to authenticate data" (wrong key or tampered data)
    return null;
  }
}

module.exports = {
  encrypt,
  decrypt,
};

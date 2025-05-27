const crypto = require('crypto');

/**
 * Generates a random alphanumeric string of specified length.
 * @param {number} length The desired length of the token. Default is 15.
 * @returns {string} The generated alphanumeric token.
 */
function generateAlphanumericToken(length = 15) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

/**
 * Generates a cryptographically strong, URL-safe token.
 * @param {number} bytes Length of the random bytes to generate. Default is 32.
 * @returns {string} Hexadecimal string representation of the token.
 */
function generateSecureToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
  generateAlphanumericToken, // As requested for 8-15 char alphanumeric
  generateSecureToken,       // A more secure option
};

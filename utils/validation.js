/**
 * Validates a password based on the following policy:
 * - Minimum length 8 characters.
 * - Must contain at least three of the following:
 *   - Uppercase letter (A-Z)
 *   - Lowercase letter (a-z)
 *   - Number (0-9)
 *   - Special character (e.g., !@#$%^&*)
 * @param {string} password The password to validate.
 * @returns {boolean} True if the password meets the policy, false otherwise.
 */
function isValidPassword(password) {
  if (!password || password.length < 8) {
    return false;
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  // Adjusted special character regex to be more inclusive as per common policies
  const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`£€¥§°]/.test(password);

  const conditionsMet = [hasUppercase, hasLowercase, hasNumber, hasSpecialChar].filter(Boolean).length;

  return conditionsMet >= 3;
}

/**
 * Basic email validation.
 * For more robust validation, consider a library like 'validator'.
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
    if (!email) return false;
    // Basic regex for email validation (not exhaustive but covers common cases)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

module.exports = {
  isValidPassword,
  isValidEmail,
};

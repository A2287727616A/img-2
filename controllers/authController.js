const axios = require('axios');
const crypto = require('crypto');
const { User } = require('../models'); // Assuming models/index.js exports User
const logger = require('../config/logger');
const transporter = require('../config/mailer');
const { isValidPassword, isValidEmail } = require('../utils/validation');
const { generateSecureToken } = require('../utils/token'); // Using secure token

const register = async (req, res) => {
  const { email, password } = req.body;
  const turnstileToken = req.body['cf-turnstile-response'];
  const clientIp = req.ip;

  // 1. Cloudflare Turnstile Verification
  if (!turnstileToken) {
    logger.warn('Turnstile token missing for registration attempt.', { email, ip: clientIp });
    return res.status(400).json({ message: 'CAPTCHA verification failed. Please try again.' });
  }

  try {
    const turnstileResponse = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      secret: process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY,
      response: turnstileToken,
      remoteip: clientIp,
    }, {
      headers: { 'Content-Type': 'application/json' }
    });

    if (!turnstileResponse.data.success) {
      logger.warn('Turnstile verification failed.', {
        email,
        ip: clientIp,
        'error-codes': turnstileResponse.data['error-codes'],
      });
      return res.status(400).json({ message: 'CAPTCHA verification failed. Please try again.' });
    }
    logger.info('Turnstile verification successful.', { email, ip: clientIp });

  } catch (error) {
    logger.error('Error during Turnstile verification:', {
      message: error.message,
      stack: error.stack,
      email,
      ip: clientIp,
    });
    return res.status(500).json({ message: 'Error verifying CAPTCHA. Please try again later.' });
  }

  // 2. Input Validation
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ message: 'Invalid email format.' });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({
      message: 'Password does not meet policy requirements. Minimum 8 characters, and at least three of: uppercase, lowercase, number, special character.',
    });
  }

  try {
    // 3. Check if User Exists
    const existingUser = await User.scope('withSensitiveInfo').findOne({ where: { email } });
    if (existingUser) {
      // If user exists but is not verified, we could resend verification.
      // For now, simple conflict.
      logger.info('Registration attempt for existing email.', { email });
      return res.status(409).json({ message: 'User with this email already exists.' });
    }

    // 4. Hash Password - Handled by User model hook (beforeCreate)

    // 5. Generate Email Verification Token
    const verificationToken = generateSecureToken(); // Using 32-byte hex
    const verificationTokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // 6. Create User Record
    // Password will be hashed by the hook in User.js
    const newUser = await User.create({
      email,
      password_hash: password, // Pass plain password, hook will hash it
      verification_token: verificationToken,
      verification_token_expires_at: verificationTokenExpiresAt,
      is_verified: false,
      role: 'user', // Default role
    });
    logger.info('New user record created, pending verification.', { userId: newUser.id, email });

    // 7. Send Verification Email
    // Construct verification URL
    // Ensure APP_URL does not end with a slash and does not include https:// if it's added here
    let appUrl = process.env.APP_URL || 'img.memory-echoes.cn';
    if (appUrl.startsWith('https://')) {
        appUrl = appUrl.substring(8);
    }
    if (appUrl.endsWith('/')) {
        appUrl = appUrl.slice(0, -1);
    }
    const verificationUrl = `https://${appUrl}/verify-email?token=${verificationToken}`;


    const mailOptions = {
      to: newUser.email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Verify Your Email Address for Memory Echoes',
      html: `
        <p>Welcome to Memory Echoes!</p>
        <p>Please click the link below to verify your email address and activate your account. This link is valid for 15 minutes.</p>
        <p><a href="${verificationUrl}" target="_blank">Verify Email Address</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Link: ${verificationUrl}</p>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
      logger.info(`Verification email sent to ${newUser.email}.`, { userId: newUser.id });
    } catch (mailError) {
      logger.error('Failed to send verification email:', {
        userId: newUser.id,
        email: newUser.email,
        message: mailError.message,
        stack: mailError.stack,
      });
      // Note: User is already created. Consider implications.
      // For now, we will still return 201, but log the email error.
      // A more robust system might queue the email for retry or alert admins.
    }

    // 8. Response
    return res.status(201).json({
      message: 'Registration successful. Please check your email to verify your account.',
      userId: newUser.id, // Optionally return user ID
    });

  } catch (error) {
    logger.error('Error during user registration process:', {
      message: error.message,
      stack: error.stack,
      email,
    });
    if (error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError') {
      return res.status(400).json({ message: 'Validation error or email already in use.', errors: error.errors });
    }
    return res.status(500).json({ message: 'An error occurred during registration. Please try again later.' });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.query;

  // 1. Validate Token Presence
  if (!token) {
    logger.warn('Verification attempt with missing token.', { ip: req.ip });
    return res.status(400).json({ message: 'Verification token is missing.' });
  }

  try {
    // 2. Find User by Token
    // It's important to use a scope that includes sensitive fields if needed,
    // but for verification, default scope is usually fine.
    // However, verification_token might be excluded by defaultScope.
    // Let's use 'withSensitiveInfo' to be sure, or ensure verification_token is not in exclude list.
    // The User model's defaultScope excludes verification_token, so we need a different scope.
    const user = await User.scope('withSensitiveInfo').findOne({ where: { verification_token: token } });

    // 3. Check if User Exists
    if (!user) {
      logger.warn('Invalid verification token received.', { token, ip: req.ip });
      return res.status(400).json({ message: 'Invalid or expired verification token.' });
    }

    // 4. Check Token Expiry
    if (new Date(user.verification_token_expires_at) < new Date()) {
      logger.info('Expired verification token used.', { userId: user.id, email: user.email, token });
      // Optional: Clean up expired token for this user to prevent reuse or clutter.
      // This could also be handled by a separate cron job that cleans up all expired tokens.
      // await user.update({
      //   verification_token: null,
      //   verification_token_expires_at: null,
      // });
      return res.status(400).json({ message: 'Verification token has expired. Please request a new one.' });
    }

    // 5. Update User Record
    user.is_verified = true;
    user.verification_token = null;
    user.verification_token_expires_at = null;
    // Potentially also set email_change_freeze_until if this is a new email verification after a change request
    // user.email_change_freeze_until = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    await user.save();
    logger.info('Email successfully verified.', { userId: user.id, email: user.email });

    // 6. Success Response
    // For an API, a JSON response is standard.
    // If this were a full-stack app with server-side rendering, a redirect might be used.
    return res.status(200).json({ message: 'Email successfully verified. You can now log in.' });

  } catch (error) {
    logger.error('Error during email verification:', {
      message: error.message,
      stack: error.stack,
      token,
      ip: req.ip,
    });
    return res.status(500).json({ message: 'An error occurred during email verification. Please try again later.' });
  }
};

const bcrypt = require('bcrypt');
const jwt =jsonwebtoken');
const { UserIp } = require('../models'); // User model is already imported

const login = async (req, res) => {
  const { email, password } = req.body;
  // const turnstileToken = req.body['cf-turnstile-response']; // Handled by middleware
  const clientIp = req.ip;
  const userAgent = req.headers['user-agent'];

  // 1. Cloudflare Turnstile Verification - Now handled by middleware

  // 2. Input Validation
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    // 3. Find User by Email
    const user = await User.scope('withSensitiveInfo').findOne({ where: { email } });

    if (!user) {
      logger.warn('Login attempt for non-existent email.', { email, ip: clientIp });
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // 4. Check Account Verification Status
    if (!user.is_verified) {
      logger.info('Login attempt for unverified account.', { userId: user.id, email, ip: clientIp });
      return res.status(403).json({ message: 'Account not verified. Please check your email.' });
    }

    // 5. Check Ban Status
    if (user.is_banned) {
      logger.info('Login attempt by banned user (manual ban).', { userId: user.id, email, ip: clientIp, reason: user.ban_reason });
      return res.status(403).json({ message: `您的账户已被暂停。原因：${user.ban_reason || '无特定原因'}。如有疑问，请联系管理员。` });
    }
    if (user.auto_banned_at) {
      logger.info('Login attempt by banned user (auto ban).', { userId: user.id, email, ip: clientIp, reason: user.auto_ban_reason });
      return res.status(403).json({ message: `您的账户因违反安全策略已被系统自动暂停。原因：${user.auto_ban_reason || '无特定原因'}。您可以尝试通过邮件申请解封，或联系管理员。` });
    }

    // 6. Verify Password
    const isPasswordValid = await user.validPassword(password); // Assumes validPassword method exists on User model
    if (!isPasswordValid) {
      // Increment failed_login_attempts and set last_failed_login_at (basic implementation)
      // A more advanced implementation would involve locking the account after too many attempts.
      user.failed_login_attempts = (user.failed_login_attempts || 0) + 1;
      user.last_failed_login_at = new Date();
      await user.save(); // Save these changes

      logger.warn('Invalid password attempt.', { userId: user.id, email, ip: clientIp });
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    // 7. Successful Login - Reset failed attempts
    if (user.failed_login_attempts > 0) {
      user.failed_login_attempts = 0;
      // user.last_failed_login_at = null; // Or keep it for record, depends on policy
      await user.save();
    }

    // 8. Session/JWT Generation
    const sessionId = crypto.randomBytes(16).toString('hex'); // Unique ID for this session/token
    const tokenPayload = {
      id: user.id,
      email: user.email,
      role: user.role,
      jti: sessionId, // JWT ID claim, can be used as session_id
    };
    const token = jwt.sign(
      tokenPayload,
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
    );

    // 8. Check for Pending Deletion (before 2FA check for logical flow)
    if (user.account_deletion_requested_at &&
        user.account_deletion_token_expires_at && // This field now stores the final deletion time
        new Date(user.account_deletion_token_expires_at) > new Date()) {
      
      logger.info('Login attempt by user with account scheduled for deletion.', { 
        userId: user.id, 
        email, 
        deletionScheduledAt: user.account_deletion_token_expires_at.toISOString() 
      });
      
      return res.status(202).json({ 
        message: 'Account scheduled for deletion.',
        deletion_scheduled_at: user.account_deletion_token_expires_at.toISOString(),
        user: { id: user.id, email: user.email, role: user.role },
      });
    }

    // 9. Check if 2FA is Enabled
    // User model should already have two_factor_enabled, two_factor_secret loaded via 'withSensitiveInfo' scope
    if (user.two_factor_enabled && user.two_factor_secret) { // Check secret exists to ensure setup was completed
      logger.info(`2FA enabled for user ${user.id}. Prompting for 2FA token.`);
      // Do NOT issue JWT yet. Send a response indicating 2FA is required.
      return res.status(202).json({ // Using 202 (Accepted) or a custom status/flag
        status: '2FA_REQUIRED', // Custom status for frontend to handle
        message: 'Two-Factor Authentication required. Please provide your authentication code.',
        userId: user.id, // Send userId to be used in the /verify-2fa call
      });
    }
    
    // If 2FA is not enabled, proceed to JWT generation (original step 9, now step 10)
    // 10. Session/JWT Generation
    const sessionId = crypto.randomBytes(16).toString('hex'); // Unique ID for this session/token
    const tokenPayload = {
      id: user.id,
      email: user.email,
      role: user.role,
      jti: sessionId, // JWT ID claim, can be used as session_id
    };
    const token = jwt.sign(
      tokenPayload,
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
    );

    // 10. Log Login IP and User Agent
    try {
      await UserIp.create({
        user_id: user.id,
        ip_address: clientIp,
        user_agent: userAgent,
        session_id: sessionId, // Using JTI as session_id
        is_active_session: true,
        last_login_at: new Date(),
        last_activity_at: new Date(),
      });
      logger.info('User IP and agent logged.', { userId: user.id, ip: clientIp, sessionId });
    } catch (logError) {
      logger.error('Failed to log user IP and agent:', {
        userId: user.id,
        message: logError.message,
        stack: logError.stack,
      });
      // Continue with login even if IP logging fails, but log the error.
    }

    // 11. Response (normal login)
    logger.info('User logged in successfully.', { userId: user.id, email, ip: clientIp });
    res.status(200).json({
      message: 'Login successful.',
      user: { // Return non-sensitive user info
        id: user.id,
        email: user.email,
        role: user.role,
      },
      token,
    });

  } catch (error) {
    logger.error('Error during login process:', {
      message: error.message,
      stack: error.stack,
      email,
      ip: clientIp,
    });
    return res.status(500).json({ message: 'An error occurred during login. Please try again later.' });
  }
};


const { generateSecureToken } = require('../utils/token'); // Already used for verification token

const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  const genericSuccessMessage = "If an account with that email exists and is verified, a password reset link has been sent.";

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }
  if (!isValidEmail(email)) { // Assuming isValidEmail is imported or available
    return res.status(400).json({ message: 'Invalid email format.' });
  }

  try {
    const user = await User.findOne({ where: { email } }); // Default scope is fine here

    if (!user || !user.is_verified) {
      logger.info('Password reset request for non-existent or unverified email.', { email, ip: req.ip });
      return res.status(200).json({ message: genericSuccessMessage });
    }

    // Generate Reset Token
    const resetToken = generateSecureToken(); // e.g., 32-byte hex
    const resetTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Update User Record
    user.reset_password_token = resetToken;
    user.reset_password_token_expires_at = resetTokenExpiresAt;
    await user.save(); // This will use default scope, ensure it doesn't strip fields if 'withSensitiveInfo' was used to fetch.
                       // In this case, we fetched with default, and are setting fields not in defaultScope's exclude list.

    logger.info('Password reset token generated and saved for user.', { userId: user.id, email });

    // Send Reset Email
    let appUrl = process.env.APP_URL || 'img.memory-echoes.cn';
    if (appUrl.startsWith('https://')) {
        appUrl = appUrl.substring(8);
    }
    if (appUrl.endsWith('/')) {
        appUrl = appUrl.slice(0, -1);
    }
    const resetUrl = `https://${appUrl}/reset-password?token=${resetToken}`; // Assumes a frontend route

    const mailOptions = {
      to: user.email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Password Reset Request for Memory Echoes',
      html: `
        <p>You requested a password reset for your Memory Echoes account.</p>
        <p>Please click the link below to reset your password. This link is valid for 1 hour.</p>
        <p><a href="${resetUrl}" target="_blank">Reset Password</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Link: ${resetUrl}</p>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
      logger.info(`Password reset email sent to ${user.email}.`, { userId: user.id });
    } catch (mailError) {
      logger.error('Failed to send password reset email:', {
        userId: user.id,
        email: user.email,
        message: mailError.message,
        stack: mailError.stack,
      });
      // Still return generic success message
    }

    return res.status(200).json({ message: genericSuccessMessage });

  } catch (error) {
    logger.error('Error during password reset request:', {
      message: error.message,
      stack: error.stack,
      email,
      ip: req.ip,
    });
    // Still return generic success message to prevent information leakage
    return res.status(200).json({ message: genericSuccessMessage });
  }
};

const resetPassword = async (req, res) => {
  const { token, new_password } = req.body;

  // 1. Validation
  if (!token || !new_password) {
    return res.status(400).json({ message: 'Token and new password are required.' });
  }
  if (!isValidPassword(new_password)) { // Assuming isValidPassword is imported
    return res.status(400).json({
      message: 'New password does not meet policy requirements. Minimum 8 characters, and at least three of: uppercase, lowercase, number, special character.',
    });
  }

  try {
    // 2. Find User by Reset Token
    // reset_password_token is excluded by defaultScope, so 'withSensitiveInfo' is needed.
    const user = await User.scope('withSensitiveInfo').findOne({ where: { reset_password_token: token } });

    if (!user) {
      logger.warn('Invalid or non-existent password reset token used.', { token, ip: req.ip });
      return res.status(400).json({ message: 'Invalid or expired password reset token.' });
    }

    // 3. Check Token Expiry
    if (new Date(user.reset_password_token_expires_at) < new Date()) {
      logger.info('Expired password reset token used.', { userId: user.id, email: user.email, token });
      user.reset_password_token = null;
      user.reset_password_token_expires_at = null;
      await user.save(); // Clear the expired token
      return res.status(400).json({ message: 'Password reset token has expired.' });
    }

    // 4. Update Password
    // The User model's beforeUpdate hook will hash the password.
    user.password_hash = new_password; // Assign plain password, hook handles hashing.
    user.reset_password_token = null;
    user.reset_password_token_expires_at = null;
    // Optional: Consider setting email_change_freeze_until or other security flags if needed.
    // user.failed_login_attempts = 0; // Also reset failed login attempts

    await user.save();
    logger.info('Password successfully reset for user.', { userId: user.id, email: user.email });

    // 5. Send Confirmation Email
    const mailOptions = {
      to: user.email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Your Memory Echoes Password Has Been Reset',
      html: `
        <p>Hello ${user.email},</p>
        <p>This email confirms that the password for your Memory Echoes account has been successfully reset.</p>
        <p>If you did not make this change, please contact our support team immediately.</p>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
      logger.info(`Password reset confirmation email sent to ${user.email}.`, { userId: user.id });
    } catch (mailError) {
      logger.error('Failed to send password reset confirmation email:', {
        userId: user.id,
        email: user.email,
        message: mailError.message,
        stack: mailError.stack,
      });
      // The password was reset, so this is a non-critical error in terms of flow.
    }

    // (Optional Enhancement): Invalidate other active sessions/JWTs for this user.
    // This would involve a more complex session management system, e.g., storing JTI in UserIp and marking old ones inactive.

    // 6. Response
    return res.status(200).json({ message: 'Password has been reset successfully.' });

  } catch (error) {
    logger.error('Error during password reset:', {
      message: error.message,
      stack: error.stack,
      token,
      ip: req.ip,
    });
    return res.status(500).json({ message: 'An error occurred while resetting your password. Please try again later.' });
  }
};


const { decrypt } = require('../utils/encryption'); // Assuming encryption.js is in utils
const speakeasy = require('speakeasy'); // For TOTP verification

const verify2FA = async (req, res) => {
  const { userId, token: twoFactorToken } = req.body; // 'token' from request is the 2FA code

  if (!userId || !twoFactorToken) {
    return res.status(400).json({ message: 'User ID and 2FA token are required.' });
  }

  try {
    const user = await User.scope('withSensitiveInfo').findByPk(userId);
    if (!user || !user.two_factor_enabled || !user.two_factor_secret) {
      logger.warn('2FA verification attempt for user without 2FA enabled or secret missing.', { userId });
      return res.status(401).json({ message: '2FA is not enabled for this account or setup is incomplete.' });
    }

    // Decrypt the stored 2FA secret
    const decryptedSecret = decrypt(user.two_factor_secret);
    if (!decryptedSecret) {
      logger.error('Failed to decrypt 2FA secret for user.', { userId });
      return res.status(500).json({ message: 'Error verifying 2FA. Please contact support.' });
    }

    // 1. Try verifying as a TOTP token
    const isValidTOTP = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32', // Assuming the secret was stored/handled as base32
      token: twoFactorToken,
      window: 1,
    });

    if (isValidTOTP) {
      logger.info(`TOTP verification successful for user ${userId}.`);
      // Proceed to issue JWT and log login
      return issueJwtAndLogLogin(req, res, user);
    }

    // 2. If TOTP fails, try verifying as a recovery code
    const storedHashedRecoveryCodes = user.two_factor_recovery_codes; // This is a JSON string of hashed codes
    if (storedHashedRecoveryCodes && Array.isArray(storedHashedRecoveryCodes)) { // Ensure it's an array (after JSON.parse in getter)
      let recoveryCodeMatch = false;
      let matchedCodeIndex = -1;

      for (let i = 0; i < storedHashedRecoveryCodes.length; i++) {
        const hashedCode = storedHashedRecoveryCodes[i];
        // Compare the provided token (plain) against the stored hash
        if (await bcrypt.compare(twoFactorToken, hashedCode)) {
          recoveryCodeMatch = true;
          matchedCodeIndex = i;
          break;
        }
      }

      if (recoveryCodeMatch) {
        logger.info(`Recovery code verification successful for user ${userId}.`);
        // Mark recovery code as used by removing it from the array
        const updatedRecoveryCodes = [...storedHashedRecoveryCodes];
        updatedRecoveryCodes.splice(matchedCodeIndex, 1);
        user.two_factor_recovery_codes = JSON.stringify(updatedRecoveryCodes); // Store back as JSON string
        
        // Check if all recovery codes are used up, and if so, send a warning email
        if (updatedRecoveryCodes.length === 0) {
            logger.warn(`User ${userId} has used their last 2FA recovery code.`);
            // Send email notification
            const mailOptions = {
                to: user.email,
                from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
                subject: 'All 2FA Recovery Codes Used - Memory Echoes Account Security',
                html: `
                    <p>Hello ${user.email},</p>
                    <p>You have just used your last Two-Factor Authentication (2FA) recovery code for your Memory Echoes account.</p>
                    <p>For continued account security, we strongly recommend that you log in and either:</p>
                    <ul>
                        <li>Disable and then re-enable 2FA to generate a new set of recovery codes.</li>
                        <li>Ensure your primary authenticator app is accessible.</li>
                    </ul>
                    <p>If you lose access to your authenticator app and have no recovery codes, you may lose access to your account.</p>
                    <p>If you did not authorize this action, please contact support immediately.</p>
                `,
            };
            try {
                await transporter.sendMail(mailOptions);
                logger.info(`"Last recovery code used" notification sent to ${user.email} for user ${userId}.`);
            } catch (mailError) {
                logger.error('Failed to send "last recovery code used" notification email:', { userId, email: user.email, mailError});
            }
        }
        await user.save();
        return issueJwtAndLogLogin(req, res, user); // Proceed to issue JWT
      }
    }

    // If both TOTP and recovery code fail
    logger.warn('Invalid 2FA token or recovery code provided.', { userId });
    // Increment failed login attempts for 2FA? Could be a feature. For now, just deny.
    return res.status(401).json({ message: 'Invalid 2FA token or recovery code.' });

  } catch (error) {
    logger.error('Error during 2FA verification:', {
      userId,
      message: error.message,
      stack: error.stack,
    });
    return res.status(500).json({ message: 'An error occurred during 2FA verification.' });
  }
};

// Helper function to issue JWT and log login (extracted from original login for reuse)
async function issueJwtAndLogLogin(req, res, user) {
  const clientIp = req.ip;
  const userAgent = req.headers['user-agent'];
  const sessionId = crypto.randomBytes(16).toString('hex');

  const tokenPayload = {
    id: user.id,
    email: user.email,
    role: user.role,
    jti: sessionId,
  };
  const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1d' });

  try {
    await UserIp.create({
      user_id: user.id,
      ip_address: clientIp,
      user_agent: userAgent,
      session_id: sessionId,
      is_active_session: true,
      last_login_at: new Date(), // Or use existing if this is just 2FA step after initial login
      last_activity_at: new Date(),
    });
    logger.info('User IP and agent logged after 2FA.', { userId: user.id, ip: clientIp, sessionId });
  } catch (logError) {
    logger.error('Failed to log user IP and agent after 2FA:', { userId: user.id, message: logError.message });
  }

  res.status(200).json({
    message: 'Login successful (2FA verified).',
    user: { id: user.id, email: user.email, role: user.role },
    token,
  });
}


module.exports = {
  register,
  verifyEmail,
  login,
  requestPasswordReset,
  resetPassword,
  verify2FA,
};

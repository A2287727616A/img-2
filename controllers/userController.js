const { User } = require('../models');
const logger = require('../config/logger');
const { generateAlphanumericToken, generateSecureToken } = require('../utils/token');
const { isValidEmail, isValidPassword } = require('../utils/validation');
const transporter = require('../config/mailer');
const bcrypt = require('bcrypt'); // Needed for password verification if not using user.validPassword directly in some cases

// Functions for email change will be added here in subsequent steps:
// - requestEmailChangeOTP
// - requestEmailChange
// - verifyNewEmail

const requestEmailChangeOTP = async (req, res) => {
  const userId = req.user.id; // From isAuthenticated middleware

  try {
    // User is already fetched by isAuthenticated, but let's fetch again to ensure fresh data
    // and access to sensitive fields if needed by model hooks or methods.
    // For OTP, we need the current email.
    const user = await User.scope('withSensitiveInfo').findByPk(userId);
    if (!user) {
      // Should not happen if isAuthenticated is working correctly
      logger.warn('User not found for OTP request after authentication.', { userId });
      return res.status(404).json({ message: 'User not found.' });
    }

    // Generate OTP
    const otp = generateAlphanumericToken(8); // 8-character alphanumeric OTP
    const otpExpiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Store OTP and expiry in user record
    user.login_otp_token = otp;
    user.login_otp_token_expires_at = otpExpiresAt;
    await user.save();

    logger.info(`OTP generated for email change request for user ${userId}. OTP: ${otp}`); // Log OTP in dev/debug

    // Send OTP to user's current email
    const mailOptions = {
      to: user.email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Verify Your Identity to Change Email Address - Memory Echoes',
      html: `
        <p>Hello,</p>
        <p>You requested to change the email address associated with your Memory Echoes account.</p>
        <p>To verify your identity, please use the following One-Time Password (OTP):</p>
        <h2>${otp}</h2>
        <p>This OTP is valid for 15 minutes.</p>
        <p>If you did not request this, please ignore this email or contact support if you have concerns.</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    logger.info(`Email change OTP sent to ${user.email} for user ${userId}.`);

    return res.status(200).json({ message: 'OTP sent to your current email address.' });

  } catch (error) {
    logger.error('Error requesting email change OTP:', {
      userId,
      message: error.message,
      stack: error.stack,
    });
    return res.status(500).json({ message: 'An error occurred while requesting OTP. Please try again.' });
  }
};


const requestEmailChange = async (req, res) => {
  const userId = req.user.id;
  const { current_password, otp, new_email } = req.body;

  // 1. Basic Input Validation
  if (!current_password || !otp || !new_email) {
    return res.status(400).json({ message: 'Current password, OTP, and new email are required.' });
  }
  if (!isValidEmail(new_email)) {
    return res.status(400).json({ message: 'Invalid new email format.' });
  }

  try {
    const user = await User.scope('withSensitiveInfo').findByPk(userId);
    if (!user) {
      logger.warn('User not found for email change request after authentication.', { userId });
      return res.status(404).json({ message: 'User not found.' });
    }

    // 2. Verify Current Password
    const isPasswordValid = await user.validPassword(current_password);
    if (!isPasswordValid) {
      logger.warn('Invalid current password during email change request.', { userId });
      return res.status(401).json({ message: 'Invalid current password.' });
    }

    // 3. Verify OTP (from old email)
    if (user.login_otp_token !== otp) {
      logger.warn('Invalid OTP during email change request.', { userId });
      // Clear OTP after one incorrect attempt to prevent brute-forcing the same OTP
      user.login_otp_token = null;
      user.login_otp_token_expires_at = null;
      await user.save();
      return res.status(400).json({ message: 'Invalid OTP.' });
    }
    if (new Date(user.login_otp_token_expires_at) < new Date()) {
      logger.info('Expired OTP used during email change request.', { userId });
      user.login_otp_token = null;
      user.login_otp_token_expires_at = null;
      await user.save();
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    // Clear OTP after successful validation
    user.login_otp_token = null;
    user.login_otp_token_expires_at = null;

    // 4. Validate New Email
    if (user.email === new_email) {
      return res.status(400).json({ message: 'New email address must be different from your current email.' });
    }
    const existingUserWithNewEmail = await User.findOne({ where: { email: new_email } });
    if (existingUserWithNewEmail) {
      logger.info('Attempt to change email to an already registered email.', { userId, new_email });
      return res.status(409).json({ message: 'This email address is already in use by another account.' });
    }

    // 5. Generate New Email Verification Token
    const emailChangeToken = generateSecureToken(); // Using secure token
    const emailChangeTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // 6. Update User Record (Pending State)
    user.pending_email = new_email;
    user.email_change_token = emailChangeToken;
    user.email_change_token_expires_at = emailChangeTokenExpiresAt;
    await user.save();
    logger.info(`Pending email change initiated for user ${userId} to ${new_email}.`);

    // 7. Send Verification Email to New Email Address
    let appUrl = process.env.APP_URL || 'img.memory-echoes.cn';
    if (appUrl.startsWith('https://')) appUrl = appUrl.substring(8);
    if (appUrl.endsWith('/')) appUrl = appUrl.slice(0, -1);
    const verificationUrl = `https://${appUrl}/verify-new-email?token=${emailChangeToken}`;

    const mailToNewOptions = {
      to: new_email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Confirm Your New Email Address for Memory Echoes',
      html: `
        <p>Hello,</p>
        <p>You requested to change your Memory Echoes account's email address to this one (${new_email}).</p>
        <p>Please click the link below to confirm this new email address. This link is valid for 1 hour.</p>
        <p><a href="${verificationUrl}" target="_blank">Confirm New Email Address</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Link: ${verificationUrl}</p>
      `,
    };
    await transporter.sendMail(mailToNewOptions);
    logger.info(`Verification email sent to new address ${new_email} for user ${userId}.`);

    // 8. Notify Old Email (Request Initiated)
    const mailToOldOptions = {
      to: user.email, // Current (old) email
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Email Change Request Initiated - Memory Echoes',
      html: `
        <p>Hello,</p>
        <p>A request has been initiated to change the email address for your Memory Echoes account from ${user.email} to ${new_email}.</p>
        <p>A verification email has been sent to ${new_email}. Please follow the instructions in that email to confirm the change.</p>
        <p>If you did not authorize this change, please secure your account immediately (e.g., change your password) and contact support.</p>
      `,
    };
    await transporter.sendMail(mailToOldOptions);
    logger.info(`Notification of email change initiation sent to old address ${user.email} for user ${userId}.`);

    // 9. Response
    return res.status(200).json({ message: `Verification link sent to new email address. Please check ${new_email} to confirm.` });

  } catch (error) {
    logger.error('Error requesting email change:', {
      userId,
      new_email_attempt: new_email,
      message: error.message,
      stack: error.stack,
    });
    // Ensure OTP fields are cleared on error if not already done
    try {
        const userForCleanup = await User.scope('withSensitiveInfo').findByPk(userId);
        if(userForCleanup && userForCleanup.login_otp_token) {
            userForCleanup.login_otp_token = null;
            userForCleanup.login_otp_token_expires_at = null;
            await userForCleanup.save();
        }
    } catch (cleanupError) {
        logger.error('Error during cleanup of OTP fields in requestEmailChange error handler:', {userId, cleanupError});
    }
    return res.status(500).json({ message: 'An error occurred. Please try again.' });
  }
};

const verifyNewEmail = async (req, res) => {
  const { token } = req.query;

  if (!token) {
    logger.warn('Verify new email attempt with missing token.', { ip: req.ip });
    return res.status(400).json({ message: 'Verification token is missing.' });
  }

  try {
    const user = await User.scope('withSensitiveInfo').findOne({ where: { email_change_token: token } });

    if (!user) {
      logger.warn('Invalid or non-existent new email verification token used.', { token, ip: req.ip });
      return res.status(400).json({ message: 'Invalid or expired verification token.' });
    }

    if (new Date(user.email_change_token_expires_at) < new Date()) {
      logger.info('Expired new email verification token used.', { userId: user.id, email: user.pending_email, token });
      // Clear the pending state as the token expired
      user.pending_email = null;
      user.email_change_token = null;
      user.email_change_token_expires_at = null;
      await user.save();
      return res.status(400).json({ message: 'Verification token has expired. Please restart the email change process.' });
    }

    // Token is valid and not expired.
    const oldEmail = user.email;
    const newVerifiedEmail = user.pending_email;

    // Set Freeze Period: 168 hours (7 days)
    user.email_change_freeze_until = new Date(Date.now() + 168 * 60 * 60 * 1000);
    user.email_change_token = null; // Clear the token as it's used
    user.email_change_token_expires_at = null;
    // Note: user.pending_email remains as is, user.email is not changed yet.
    await user.save();
    logger.info(`New email ${newVerifiedEmail} verified for user ${user.id}. Freeze period started.`);

    // Notify Old Email (New Email Verified, Freeze Period Started)
    const mailToOldOptions = {
      to: oldEmail,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'New Email Address Verified - Action Required for Finalization - Memory Echoes',
      html: `
        <p>Hello,</p>
        <p>Your new email address (<strong>${newVerifiedEmail}</strong>) for your Memory Echoes account has been successfully verified.</p>
        <p>To complete the change, your account's email address will be officially updated to <strong>${newVerifiedEmail}</strong> in approximately 168 hours (7 days).</p>
        <p>During this freeze period, some account functionalities might be limited for security reasons.</p>
        <p>If you recognize this activity, no further action is needed from your side. The change will proceed automatically.</p>
        <p>If you did NOT authorize this or suspect suspicious activity, please contact our support team immediately or take steps to secure your account (e.g., by attempting a password reset if you still have access to this old email).</p>
      `,
    };
    try {
      await transporter.sendMail(mailToOldOptions);
      logger.info(`Notification of new email verification and freeze period sent to old address ${oldEmail} for user ${user.id}.`);
    } catch (mailError) {
        logger.error('Failed to send new email verification notification to old email:', { userId: user.id, oldEmail, mailError});
    }
    
    // Notify New Email (Verification Success, Freeze Period Info)
    const mailToNewOptions = {
      to: newVerifiedEmail,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'New Email Address Successfully Verified - Memory Echoes',
      html: `
        <p>Hello,</p>
        <p>This email confirms that your new email address (<strong>${newVerifiedEmail}</strong>) for your Memory Echoes account has been successfully verified.</p>
        <p>The email address for your account will be officially updated to <strong>${newVerifiedEmail}</strong> in approximately 168 hours (7 days) from the time of verification.</p>
        <p>During this security freeze period, some account functionalities might be limited.</p>
        <p>No further action is needed from your side. The change will proceed automatically after the freeze period.</p>
        <p>Thank you for using Memory Echoes.</p>
      `,
    };
     try {
      await transporter.sendMail(mailToNewOptions);
      logger.info(`Confirmation of new email verification sent to new address ${newVerifiedEmail} for user ${user.id}.`);
    } catch (mailError) {
        logger.error('Failed to send new email verification confirmation to new email:', { userId: user.id, newVerifiedEmail, mailError});
    }


    return res.status(200).json({ message: 'New email address verified. The change will be finalized after a 7-day security freeze period.' });

  } catch (error) {
    logger.error('Error verifying new email:', {
      token_attempted: token,
      message: error.message,
      stack: error.stack,
    });
    return res.status(500).json({ message: 'An error occurred. Please try again.' });
  }
};

const axios = require('axios'); // For Turnstile, if not already imported

const requestAccountDeletion = async (req, res) => {
  const userId = req.user.id;
  const { current_password } = req.body;
  const turnstileToken = req.body['cf-turnstile-response'];
  const clientIp = req.ip;

  // 1. Input Validation
  if (!current_password) {
    return res.status(400).json({ message: 'Current password is required.' });
  }

  // 2. Cloudflare Turnstile Verification
  if (process.env.NODE_ENV !== 'development') { // Skip in dev for convenience
    if (!turnstileToken) {
      logger.warn('Turnstile token missing for account deletion request.', { userId, ip: clientIp });
      return res.status(403).json({ message: 'CAPTCHA verification failed. Please try again.' });
    }
    try {
      const turnstileResponse = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        secret: process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY,
        response: turnstileToken,
        remoteip: clientIp,
      }, { headers: { 'Content-Type': 'application/json' } });

      if (!turnstileResponse.data.success) {
        logger.warn('Turnstile verification failed for account deletion.', {
          userId,
          ip: clientIp,
          'error-codes': turnstileResponse.data['error-codes'],
        });
        return res.status(403).json({ message: 'CAPTCHA verification failed. Please try again.' });
      }
      logger.info('Turnstile verification successful for account deletion.', { userId, ip: clientIp });
    } catch (error) {
      logger.error('Error during Turnstile verification for account deletion:', {
        userId,
        message: error.message,
        stack: error.stack,
        ip: clientIp,
      });
      return res.status(500).json({ message: 'Error verifying CAPTCHA. Please try again later.' });
    }
  }

  try {
    const user = await User.scope('withSensitiveInfo').findByPk(userId);
    if (!user) {
      // Should not happen if isAuthenticated is working
      logger.error('User not found for deletion request after authentication.', { userId });
      return res.status(404).json({ message: 'User not found.' });
    }

    // 3. Verify Current Password
    const isPasswordValid = await user.validPassword(current_password);
    if (!isPasswordValid) {
      logger.warn('Invalid current password during account deletion request.', { userId });
      return res.status(401).json({ message: 'Invalid current password.' });
    }

    // 4. Generate Deletion Confirmation Token
    const deletionToken = generateSecureToken(); // 32-byte hex
    const deletionTokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // 5. Update User Record
    user.account_deletion_confirmation_token = deletionToken;
    user.account_deletion_token_expires_at = deletionTokenExpiresAt;
    // Do not set account_deletion_requested_at yet. That's for stage 2.
    await user.save();
    logger.info(`Account deletion confirmation token generated for user ${userId}.`);

    // 6. Send Confirmation Email
    let appUrl = process.env.APP_URL || 'img.memory-echoes.cn';
    if (appUrl.startsWith('https://')) appUrl = appUrl.substring(8);
    if (appUrl.endsWith('/')) appUrl = appUrl.slice(0, -1);
    const confirmationUrl = `https://${appUrl}/confirm-delete-account?token=${deletionToken}`;

    const mailOptions = {
      to: user.email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Confirm Your Account Deletion Request for Memory Echoes',
      html: `
        <p>Hello ${user.email},</p>
        <p>You have requested to delete your Memory Echoes account. To confirm this decision and schedule your account for deletion, please click the link below:</p>
        <p><a href="${confirmationUrl}" target="_blank">Confirm Account Deletion</a></p>
        <p>This link is valid for 24 hours. If you do not click this link, your account will not be scheduled for deletion.</p>
        <p>If you did not request this, please secure your account (e.g., change your password) and contact support immediately.</p>
        <p>Link: ${confirmationUrl}</p>
      `,
    };
    await transporter.sendMail(mailOptions);
    logger.info(`Account deletion confirmation email sent to ${user.email} for user ${userId}.`);

    // 7. Response
    return res.status(200).json({ message: 'Confirmation email sent. Please check your email to proceed with account deletion.' });

  } catch (error) {
    logger.error('Error requesting account deletion:', {
      userId,
      message: error.message,
      stack: error.stack,
    });
    return res.status(500).json({ message: 'An error occurred. Please try again.' });
  }
};

const confirmAccountDeletion = async (req, res) => {
  const { token } = req.query;

  if (!token) {
    logger.warn('Confirm account deletion attempt with missing token.', { ip: req.ip });
    return res.status(400).json({ message: 'Deletion confirmation token is missing.' });
  }

  try {
    // account_deletion_confirmation_token is excluded by defaultScope, so 'withSensitiveInfo' is needed.
    const user = await User.scope('withSensitiveInfo').findOne({
      where: { account_deletion_confirmation_token: token },
    });

    if (!user) {
      logger.warn('Invalid or non-existent account deletion confirmation token used.', { token, ip: req.ip });
      return res.status(400).json({ message: 'Invalid or expired deletion token.' });
    }

    if (new Date(user.account_deletion_token_expires_at) < new Date()) {
      logger.info('Expired account deletion confirmation token used.', { userId: user.id, email: user.email, token });
      // Clear the expired token
      user.account_deletion_confirmation_token = null;
      user.account_deletion_token_expires_at = null;
      await user.save();
      return res.status(400).json({ message: 'Deletion token has expired. Please restart the process.' });
    }

    // Activate Cool-down
    const deletionScheduledAt = new Date();
    const deletionFinalizesAt = new Date(Date.now() + 72 * 60 * 60 * 1000); // 72 hours from now

    user.account_deletion_requested_at = deletionScheduledAt;
    user.account_deletion_token_expires_at = deletionFinalizesAt; // Re-purpose this field for final deletion time
    user.account_deletion_confirmation_token = null; // Clear the confirmation token as it's used
    // Note: Do not clear account_deletion_token_expires_at related to the *confirmation* token,
    // as we are re-purposing it for the *final deletion* time.
    // The original expiry was for the confirmation link itself.

    await user.save();
    logger.info(`Account deletion confirmed and scheduled for user ${user.id}. Final deletion at: ${deletionFinalizesAt.toISOString()}`);

    // Notify User (Deletion Scheduled)
    const mailOptions = {
      to: user.email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Your Memory Echoes Account Deletion is Scheduled',
      html: `
        <p>Hello ${user.email},</p>
        <p>You have successfully confirmed your account deletion request.</p>
        <p>Your Memory Echoes account is now scheduled for permanent deletion. This process will be finalized in approximately 72 hours, on <strong>${deletionFinalizesAt.toUTCString()}</strong>.</p>
        <p>If you wish to cancel this deletion, you can do so by logging into your account before this time. Upon logging in, you will be prompted to cancel the deletion process.</p>
        <p>If you do not log in and cancel, your account and all associated data will be permanently removed after this period.</p>
        <p>If you have any concerns or did not authorize this, please contact support immediately.</p>
      `,
    };
    await transporter.sendMail(mailOptions);
    logger.info(`Account deletion scheduled notification sent to ${user.email} for user ${user.id}.`);

    // Response
    return res.status(200).json({
      message: `Account deletion confirmed and scheduled. Your account will be permanently deleted in approximately 72 hours (around ${deletionFinalizesAt.toUTCString()}) unless you log in and cancel.`,
    });

  } catch (error) {
    logger.error('Error confirming account deletion:', {
      token_attempted: token,
      message: error.message,
      stack: error.stack,
    });
    return res.status(500).json({ message: 'An error occurred. Please try again.' });
  }
};

const cancelAccountDeletion = async (req, res) => {
  const userId = req.user.id; // From isAuthenticated middleware

  try {
    const user = await User.scope('withSensitiveInfo').findByPk(userId);
    if (!user) {
      // Should not happen if isAuthenticated is working
      logger.error('User not found for cancel deletion request after authentication.', { userId });
      return res.status(404).json({ message: 'User not found.' });
    }

    // Check if deletion was actually requested and is pending
    if (!user.account_deletion_requested_at || !user.account_deletion_token_expires_at || new Date(user.account_deletion_token_expires_at) < new Date()) {
      logger.info(`No active account deletion schedule found for user ${userId} to cancel.`);
      return res.status(400).json({ message: 'No active account deletion schedule found or it has already passed.' });
    }
    
    const oldDeletionDate = user.account_deletion_token_expires_at.toISOString();

    // Clear deletion fields
    user.account_deletion_requested_at = null;
    user.account_deletion_confirmation_token = null; // Should be null already from confirm step
    user.account_deletion_token_expires_at = null;   // This was holding the final deletion date

    await user.save();
    logger.info(`Account deletion canceled for user ${userId}. Was scheduled for ${oldDeletionDate}`);

    // Notify User (Deletion Canceled)
    const mailOptions = {
      to: user.email,
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
      subject: 'Your Memory Echoes Account Deletion Has Been Canceled',
      html: `
        <p>Hello ${user.email},</p>
        <p>This email confirms that your request to delete your Memory Echoes account has been successfully canceled.</p>
        <p>Your account will remain active. You can log in and continue using our services as usual.</p>
        <p>If you have any questions or did not request this cancellation, please contact our support team.</p>
      `,
    };
    await transporter.sendMail(mailOptions);
    logger.info(`Account deletion cancellation notification sent to ${user.email} for user ${userId}.`);

    // Response
    // Frontend should now allow normal login or issue a new token immediately.
    // For simplicity, we'll instruct to log in again.
    return res.status(200).json({ message: 'Account deletion has been canceled. You can now log in normally.' });

  } catch (error) {
    logger.error('Error canceling account deletion:', {
      userId,
      message: error.message,
      stack: error.stack,
    });
    return res.status(500).json({ message: 'An error occurred. Please try again.' });
  }
};

module.exports = {
  requestEmailChangeOTP,
  requestEmailChange,
  verifyNewEmail,
  requestAccountDeletion,
  confirmAccountDeletion,
  cancelAccountDeletion,
};

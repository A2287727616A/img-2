const { AuditLog } = require('../models');
const logger = require('../config/logger'); // Assuming logger is in config/logger.js

const ACTION_TYPES = {
  // User Authentication
  USER_LOGIN_SUCCESS: 'USER_LOGIN_SUCCESS',
  USER_LOGIN_FAIL: 'USER_LOGIN_FAIL', // Generic login fail
  USER_REGISTER_SUCCESS: 'USER_REGISTER_SUCCESS',
  USER_EMAIL_VERIFIED: 'USER_EMAIL_VERIFIED',

  // Password Management
  USER_PASSWORD_RESET_REQUEST: 'USER_PASSWORD_RESET_REQUEST',
  USER_PASSWORD_RESET_SUCCESS: 'USER_PASSWORD_RESET_SUCCESS',

  // Email Change Management
  USER_EMAIL_CHANGE_OTP_SENT: 'USER_EMAIL_CHANGE_OTP_SENT',
  USER_EMAIL_CHANGE_REQUEST_INITIATED: 'USER_EMAIL_CHANGE_REQUEST_INITIATED',
  USER_EMAIL_CHANGE_NEW_EMAIL_VERIFIED: 'USER_EMAIL_CHANGE_NEW_EMAIL_VERIFIED', // Freeze starts
  USER_EMAIL_CHANGE_FINALIZED_BY_CRON: 'USER_EMAIL_CHANGE_FINALIZED_BY_CRON',

  // Account Deletion
  USER_ACCOUNT_DELETION_REQUEST_INITIATED: 'USER_ACCOUNT_DELETION_REQUEST_INITIATED', // User requests deletion
  USER_ACCOUNT_DELETION_CONFIRMED_COOLDOWN_ON: 'USER_ACCOUNT_DELETION_CONFIRMED_COOLDOWN_ON', // User confirms via email, cool-down starts
  USER_ACCOUNT_DELETION_CANCELED: 'USER_ACCOUNT_DELETION_CANCELED', // User cancels during cool-down
  USER_ACCOUNT_DELETED_BY_CRON: 'USER_ACCOUNT_DELETED_BY_CRON', // Cron job finalizes deletion

  // Two-Factor Authentication (2FA)
  USER_2FA_SETUP_REQUESTED: 'USER_2FA_SETUP_REQUESTED', // User starts 2FA setup (QR shown)
  USER_2FA_ENABLED: 'USER_2FA_ENABLED', // User successfully verifies TOTP and enables 2FA
  USER_2FA_LOGIN_SUCCESS: 'USER_2FA_LOGIN_SUCCESS', // Successful login using TOTP
  USER_2FA_RECOVERY_LOGIN_SUCCESS: 'USER_2FA_RECOVERY_LOGIN_SUCCESS', // Successful login using recovery code
  USER_2FA_DISABLED: 'USER_2FA_DISABLED', // User disables 2FA
  USER_2FA_LAST_RECOVERY_CODE_USED: 'USER_2FA_LAST_RECOVERY_CODE_USED', // User uses their last recovery code
  IMAGE_UPLOAD_SUCCESS: 'IMAGE_UPLOAD_SUCCESS', // Successful image upload
  IMAGE_DELETED_BY_CRON_EXPIRY: 'IMAGE_DELETED_BY_CRON_EXPIRY', // Image auto-deleted by cron due to expiry
  
  // Add other specific action types as needed
  // e.g., USER_PROFILE_UPDATE, ADMIN_ACTION_BAN_USER etc.
};

/**
 * Logs an action to the audit log.
 * @param {object} data The audit data.
 * @param {number} [data.actorUserId] ID of the user performing the action.
 * @param {string} [data.actorIp] IP address of the actor.
 * @param {string} data.actionType Type of action (from ACTION_TYPES).
 * @param {number} [data.targetUserId] ID of the user being acted upon.
 * @param {string} [data.targetResourceId] ID of the resource involved.
 * @param {object} [data.details] Specific information about the action.
 */
async function logAction(data) {
  try {
    if (!data.actionType || !Object.values(ACTION_TYPES).includes(data.actionType)) {
        logger.error('Audit log attempt with invalid or missing actionType:', { actionType: data.actionType, actorUserId: data.actorUserId });
        // Optionally throw an error or handle more gracefully depending on strictness
        return;
    }

    await AuditLog.create({
      actor_user_id: data.actorUserId || null,
      actor_ip: data.actorIp || null,
      action_type: data.actionType,
      target_user_id: data.targetUserId || null,
      target_resource_id: data.targetResourceId || null,
      // The AuditLog model's 'details' setter handles JSON.stringify if the input is an object
      details: data.details || null,
    });
    // logger.debug(`Audit log created: ${data.actionType}`, { actorUserId: data.actorUserId, targetUserId: data.targetUserId });
  } catch (error) {
    logger.error('Failed to create audit log entry:', {
      errorMessage: error.message,
      errorStack: error.stack,
      originalData: data, // Log the data that failed to be audited
    });
    // Important: Do not let audit logging failure break the main operation.
  }
}

module.exports = {
  logAction,
  ACTION_TYPES,
};

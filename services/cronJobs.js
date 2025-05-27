const cron = require('node-cron');
const { User } = require('../models');
const { Op } = require('sequelize'); // To use operators like Op.lte
const logger = require('../config/logger');
const transporter = require('../config/mailer');
const { logAction, ACTION_TYPES } = require('./auditLogService'); // Added for audit logging
const dotenv = require('dotenv');

dotenv.config();

/**
 * Finds users whose email change freeze period has ended and finalizes the change.
 */
async function finalizeEmailChanges() {
  logger.info('Cron job: Starting finalizeEmailChanges...');
  try {
    const usersToUpdate = await User.scope('withSensitiveInfo').findAll({
      where: {
        pending_email: { [Op.ne]: null }, // Ensure there's a pending email
        email_change_freeze_until: {
          [Op.ne]: null, // Ensure freeze period was set
          [Op.lte]: new Date(), // Freeze period is over
        },
      },
    });

    if (usersToUpdate.length === 0) {
      logger.info('Cron job: No email changes to finalize at this time.');
      return;
    }

    logger.info(`Cron job: Found ${usersToUpdate.length} user(s) for email finalization.`);

    for (const user of usersToUpdate) {
      const oldEmail = user.email;
      const newEmail = user.pending_email;

      // Update user record
      user.email = newEmail;
      user.pending_email = null;
      user.email_change_freeze_until = null;
      user.is_verified = true; // The new email is now the primary and verified email
      // Reset email change tokens if any were left (should be cleared by verifyNewEmail)
      user.email_change_token = null;
      user.email_change_token_expires_at = null;

      await user.save();
      logger.info(`Cron job: Email for user ${user.id} successfully changed from ${oldEmail} to ${newEmail}.`);
      await logAction({
        actorUserId: null, // System Action
        actorIp: 'SYSTEM',
        actionType: ACTION_TYPES.USER_EMAIL_CHANGE_FINALIZED_BY_CRON,
        targetUserId: user.id,
        details: { oldEmail: oldEmail, newEmail: user.email }
      });

      // Notify Old Email (Final Confirmation)
      const mailToOldOptions = {
        to: oldEmail, // This email address is no longer associated with the account
        from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
        subject: 'Account Email Address Successfully Changed - Memory Echoes',
        html: `
          <p>Hello,</p>
          <p>This is a confirmation that the email address for an account previously associated with this email address (<strong>${oldEmail}</strong>) has been successfully changed to <strong>${newEmail}</strong>.</p>
          <p>If you did not authorize this change or believe this is an error, please contact our support team immediately.</p>
          <p>Thank you.</p>
        `,
      };
      try {
        await transporter.sendMail(mailToOldOptions);
        logger.info(`Cron job: Final email change notification sent to old address ${oldEmail} for user ${user.id}.`);
      } catch (error) {
        logger.error(`Cron job: Failed to send final notification to old email ${oldEmail} for user ${user.id}`, error);
      }

      // Notify New Email (Final Confirmation)
      const mailToNewOptions = {
        to: newEmail,
        from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
        subject: 'Your Memory Echoes Account Email Has Been Successfully Changed',
        html: `
          <p>Hello,</p>
          <p>This email confirms that the email address for your Memory Echoes account has been successfully updated to <strong>${newEmail}</strong>.</p>
          <p>You can now use this email address to log in and manage your account.</p>
          <p>If you have any questions, please contact our support team.</p>
          <p>Thank you for using Memory Echoes.</p>
        `,
      };
      try {
        await transporter.sendMail(mailToNewOptions);
        logger.info(`Cron job: Final email change notification sent to new address ${newEmail} for user ${user.id}.`);
      } catch (error) {
        logger.error(`Cron job: Failed to send final notification to new email ${newEmail} for user ${user.id}`, error);
      }
    }
  } catch (error) {
    logger.error('Cron job: Error during finalizeEmailChanges:', {
      message: error.message,
      stack: error.stack,
    });
  }
}

const { Image, UserIp, ApiKey, Watermark, Collection, CollectionImage, ImageReport } = require('../models'); // Import all necessary models
const { deleteMultipleObjects } = require('./s3Service'); // Import S3 deletion utility

/**
 * Processes accounts scheduled for deletion whose cool-down period has ended.
 */
async function processAccountDeletions() {
  logger.info('Cron job: Starting processAccountDeletions...');
  try {
    const usersToDelete = await User.scope('withSensitiveInfo').findAll({
      where: {
        account_deletion_requested_at: { [Op.ne]: null },
        account_deletion_token_expires_at: { // This field now stores the final deletion time
          [Op.ne]: null,
          [Op.lte]: new Date(),
        },
      },
    });

    if (usersToDelete.length === 0) {
      logger.info('Cron job: No accounts to delete at this time.');
      return;
    }

    logger.info(`Cron job: Found ${usersToDelete.length} user(s) for permanent deletion.`);

    for (const user of usersToDelete) {
      logger.info(`Cron job: Processing deletion for user ${user.id} (${user.email}).`);

      // 1. Send Final Notification (Pre-Deletion)
      const mailOptions = {
        to: user.email,
        from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM_ADDRESS}>`,
        subject: 'Your Memory Echoes Account is Being Deleted',
        html: `
          <p>Hello ${user.email},</p>
          <p>As scheduled, your Memory Echoes account and all associated data are now being permanently deleted.</p>
          <p>If you have any questions or believe this is an error, please contact support immediately (though recovery may not be possible at this stage).</p>
          <p>Thank you for having been a part of Memory Echoes.</p>
        `,
      };
      try {
        await transporter.sendMail(mailOptions);
        logger.info(`Cron job: Pre-deletion notification sent to ${user.email} for user ${user.id}.`);
      } catch (error) {
        logger.error(`Cron job: Failed to send pre-deletion notification to ${user.email} for user ${user.id}`, error);
        // Continue with deletion even if email fails
      }

      // 2. Data Cleanup
      try {
        // S3 Images
        const images = await Image.findAll({ where: { user_id: user.id } });
        if (images.length > 0) {
          const s3KeysToDelete = images.map(img => img.s3_object_key).filter(key => key);
          if (s3KeysToDelete.length > 0) {
            logger.info(`Cron job: Deleting ${s3KeysToDelete.length} S3 objects for user ${user.id}.`);
            await deleteMultipleObjects(s3KeysToDelete); // From s3Service.js
          }
          logger.info(`Cron job: Deleting ${images.length} Image records from DB for user ${user.id}.`);
          await Image.destroy({ where: { user_id: user.id } });
        }

        // Other User Data (add other models as needed)
        logger.info(`Cron job: Deleting UserIp records for user ${user.id}.`);
        await UserIp.destroy({ where: { user_id: user.id } });
        
        logger.info(`Cron job: Deleting ApiKey records for user ${user.id}.`);
        await ApiKey.destroy({ where: { user_id: user.id } });

        logger.info(`Cron job: Deleting user-specific Watermark records for user ${user.id}.`);
        await Watermark.destroy({ where: { user_id: user.id, is_global: false } }); // Only delete user's watermarks

        // Collections and their associations (CollectionImage)
        // Sequelize CASCADE on Collection should handle CollectionImage if defined correctly.
        // If not, manual deletion of CollectionImage might be needed first.
        // Assuming Collection.hasMany(CollectionImage, {onDelete: 'CASCADE'}) or similar.
        logger.info(`Cron job: Deleting Collection records for user ${user.id}.`);
        await Collection.destroy({ where: { user_id: user.id } });
        // If CollectionImage needs manual cleanup because of lack of CASCADE or specific logic:
        // const collections = await Collection.findAll({ where: { user_id: user.id }, attributes: ['id'] });
        // const collectionIds = collections.map(c => c.id);
        // if (collectionIds.length > 0) {
        //   await CollectionImage.destroy({ where: { collection_id: collectionIds }});
        // }

        logger.info(`Cron job: Deleting ImageReport records (where user is reporter) for user ${user.id}.`);
        await ImageReport.destroy({ where: { reporter_user_id: user.id } });
        // Note: We are not deleting ImageReport records where user's images are reported, as those reports might still be valid.
        // Also, reports reviewed by this user (if admin) will have reviewed_by_admin_id set to null due to User model's onDelete constraint.

        // Log before destroying user record
        await logAction({
          actorUserId: null, // System Action
          actorIp: 'SYSTEM',
          actionType: ACTION_TYPES.USER_ACCOUNT_DELETED_BY_CRON,
          targetUserId: user.id,
          details: { email: user.email, userId: user.id } // Include user.id in details for cross-referencing
        });

        // Delete User Record
        logger.info(`Cron job: Deleting User record for user ${user.id}.`);
        await user.destroy(); // This is the user instance from usersToDelete

        logger.info(`Cron job: Successfully deleted user ${user.id} and associated data.`);

      } catch (dbError) {
        logger.error(`Cron job: Error during data cleanup for user ${user.id}:`, {
          message: dbError.message,
          stack: dbError.stack,
        });
        // Decide on retry logic or marking user for manual review if cleanup fails partially.
        // For now, log and continue to next user.
      }
    }
  } catch (error) {
    logger.error('Cron job: Error during processAccountDeletions:', {
      message: error.message,
      stack: error.stack,
    });
  }
}


/**
 * Initializes and schedules cron jobs.
 */
function initializeCronJobs() {
  // Schedule finalizeEmailChanges to run, e.g., every hour
  cron.schedule('0 * * * *', () => { // Runs at the start of every hour
    logger.info('Cron job: Triggering scheduled finalizeEmailChanges.');
    finalizeEmailChanges();
  });

  // Schedule processAccountDeletions to run, e.g., every hour (or less frequently)
  // For testing, you might run it more frequently, e.g., every 5 minutes '*/5 * * * *'
  cron.schedule('5 * * * *', () => { // Runs at 5 minutes past every hour
    logger.info('Cron job: Triggering scheduled processAccountDeletions.');
    processAccountDeletions();
  });

  logger.info('Cron jobs initialized.');
}

async function deleteExpiredImages() {
  logger.info('Cron Job: Running deleteExpiredImages to remove images older than 72 hours.');
  try {
    // const cutoffDate = new Date(Date.now() - 72 * 60 * 60 * 1000); // Alternative if using uploaded_at
    const expiredImages = await Image.findAll({
      where: {
        expires_at: { [Op.lt]: new Date() },
      },
      attributes: ['id', 's3_object_key', 'user_id'], // Only fetch necessary fields
    });

    if (expiredImages.length === 0) {
      logger.info('Cron Job: No expired images found to delete at this time.');
      return;
    }

    logger.info(`Cron Job: Found ${expiredImages.length} expired images to delete.`);
    
    // Extract S3 keys. s3Service.deleteMultipleObjects expects an array of strings (keys)
    const s3KeysToDelete = expiredImages.map(img => img.s3_object_key).filter(key => key);
    const imageIdsToDelete = expiredImages.map(img => img.id);

    // Delete from S3
    if (s3KeysToDelete.length > 0) {
      const s3DeletionSuccess = await deleteMultipleObjects(s3KeysToDelete); 
      if (s3DeletionSuccess) {
        logger.info(`Cron Job: Successfully submitted deletion request to S3 for ${s3KeysToDelete.length} objects.`);
      } else {
        logger.error(`Cron Job: S3 deletion request for ${s3KeysToDelete.length} objects reported errors. See previous logs.`);
        // Potentially do not delete from DB if S3 deletion failed, or handle partially.
        // For now, we proceed to delete DB records even if S3 had errors, to prevent re-attempts on non-existent S3 keys.
        // A more robust solution might track S3 deletion failures and retry or flag them.
      }
    }

    // Delete from Database
    if (imageIdsToDelete.length > 0) {
      await Image.destroy({ where: { id: imageIdsToDelete } });
      logger.info(`Cron Job: Successfully deleted ${imageIdsToDelete.length} image records from database.`);
    }

    // Optional: Audit log for each system-deleted image
    for (const image of expiredImages) {
      await logAction({ 
        actorUserId: null, // System action
        actorIp: 'SYSTEM',
        actionType: ACTION_TYPES.IMAGE_DELETED_BY_CRON_EXPIRY, // Ensure this ACTION_TYPE is defined
        targetResourceId: image.id.toString(), // Convert ID to string if necessary
        targetUserId: image.user_id, // If you want to associate with the user who uploaded
        details: { s3_object_key: image.s3_object_key }
      });
    }

  } catch (error) {
    logger.error('Cron Job: Error in deleteExpiredImages:', { message: error.message, stack: error.stack });
  }
}


/**
 * Initializes and schedules cron jobs.
 */
function initializeCronJobs() {
  // Schedule finalizeEmailChanges to run, e.g., every hour
  cron.schedule('0 * * * *', () => { // Runs at the start of every hour
    logger.info('Cron job: Triggering scheduled finalizeEmailChanges.');
    finalizeEmailChanges();
  });

  // Schedule processAccountDeletions to run, e.g., every hour (or less frequently)
  cron.schedule('5 * * * *', () => { // Runs at 5 minutes past every hour
    logger.info('Cron job: Triggering scheduled processAccountDeletions.');
    processAccountDeletions();
  });

  // Schedule deleteExpiredImages to run hourly
  cron.schedule('10 * * * *', () => { // Runs at 10 minutes past every hour
    logger.info('Cron Job: Triggering scheduled deleteExpiredImages.');
    deleteExpiredImages();
  });

  logger.info('Cron jobs initialized.');
}

module.exports = {
  initializeCronJobs,
  finalizeEmailChanges, 
  processAccountDeletions, 
  deleteExpiredImages, // Export for potential manual trigger or testing
};

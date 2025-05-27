const { User } = require('../models'); // Assuming models/index.js exports User
const logger = require('../config/logger');
const dotenv = require('dotenv');

dotenv.config(); // Ensure environment variables are loaded

/**
 * Creates a default super_admin account if one does not already exist.
 * Reads credentials from environment variables.
 */
async function createDefaultSuperAdmin() {
  const adminEmail = process.env.DEFAULT_ADMIN_EMAIL;
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD;

  if (!adminEmail || !adminPassword) {
    logger.error('Default admin email or password not configured in environment variables. Cannot create default super admin.');
    return;
  }

  try {
    // Check if Admin Exists
    // Need to use 'withSensitiveInfo' scope if default scope excludes 'role' or other necessary fields for check
    // Assuming 'role' is not excluded by defaultScope. If it is, adjust scope.
    const existingAdmin = await User.scope('withSensitiveInfo').findOne({
      where: {
        email: adminEmail,
        role: 'super_admin',
      },
    });

    if (existingAdmin) {
      logger.info(`Default super admin with email ${adminEmail} already exists.`);
      return;
    }

    // Create Admin if Not Exists
    logger.info(`Default super admin with email ${adminEmail} not found, creating...`);

    const adminData = {
      email: adminEmail,
      password_hash: adminPassword, // Pass plain password, hook in User model will hash it
      role: 'super_admin',
      is_verified: true, // Super admin is verified by default
      verification_token: null,
      verification_token_expires_at: null,
      // Other fields like default_image_privacy will use their defaults from the model definition
    };

    const newAdmin = await User.create(adminData);
    logger.info(`Default super admin created successfully with email ${adminEmail} and ID ${newAdmin.id}.`);

  } catch (error) {
    logger.error('Error during default super admin creation:', {
      message: error.message,
      stack: error.stack,
      email: adminEmail,
    });
    // Depending on the error, you might want to throw it to stop the application startup
    // For now, just logging the error.
  }
}

module.exports = {
  createDefaultSuperAdmin,
};

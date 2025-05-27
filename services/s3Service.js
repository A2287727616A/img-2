const AWS = require('aws-sdk');
const logger = require('../config/logger');
const dotenv = require('dotenv');

dotenv.config();

// Configure AWS SDK
AWS.config.update({
  endpoint: process.env.S3_ENDPOINT,
  accessKeyId: process.env.S3_ACCESS_KEY_ID,
  secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  s3ForcePathStyle: true, // Required for some S3-compatible services like MinIO or Rainyun
  signatureVersion: 'v4',
});

const s3 = new AWS.S3();
const bucketName = process.env.S3_BUCKET_NAME;

/**
 * Deletes a single object from S3.
 * @param {string} key The key of the object to delete.
 * @returns {Promise<boolean>} True if successful, false otherwise.
 */
async function deleteObject(key) {
  if (!bucketName) {
    logger.error('S3_BUCKET_NAME is not defined. Cannot delete object.');
    return false;
  }
  if (!key) {
    logger.warn('S3 deleteObject called with no key.');
    return false;
  }

  const params = {
    Bucket: bucketName,
    Key: key,
  };

  try {
    await s3.deleteObject(params).promise();
    logger.info(`S3 object deleted successfully: ${key}`);
    return true;
  } catch (error) {
    logger.error(`Failed to delete S3 object ${key}:`, {
      message: error.message,
      stack: error.stack,
    });
    return false;
  }
}

/**
 * Deletes multiple objects from S3.
 * @param {Array<string>} keys An array of object keys to delete.
 * @returns {Promise<boolean>} True if all specified objects were deleted successfully or if keys array is empty, false if any deletion failed.
 */
async function deleteMultipleObjects(keys) {
  if (!bucketName) {
    logger.error('S3_BUCKET_NAME is not defined. Cannot delete multiple objects.');
    return false;
  }
  if (!keys || keys.length === 0) {
    logger.info('S3 deleteMultipleObjects called with no keys.');
    return true; // No objects to delete, operation is vacuously successful.
  }

  const objects = keys.map(key => ({ Key: key }));

  const params = {
    Bucket: bucketName,
    Delete: {
      Objects: objects,
      Quiet: false, // We want to see errors if any
    },
  };

  try {
    const output = await s3.deleteObjects(params).promise();
    let allSucceeded = true;

    if (output.Errors && output.Errors.length > 0) {
      output.Errors.forEach(error => {
        logger.error(`Error deleting S3 object ${error.Key}: ${error.Message}`, { code: error.Code });
        allSucceeded = false;
      });
    }

    const deletedCount = output.Deleted ? output.Deleted.length : 0;
    logger.info(`S3 deleteMultipleObjects: Attempted to delete ${keys.length} objects. Successfully deleted: ${deletedCount}. Errors: ${output.Errors ? output.Errors.length : 0}.`);
    
    return allSucceeded && (deletedCount === keys.length);

  } catch (error) {
    logger.error('Failed to delete multiple S3 objects:', {
      message: error.message,
      stack: error.stack,
    });
    return false;
  }
}

module.exports = {
  s3, // Export S3 instance for other potential uses
  deleteObject,
  deleteMultipleObjects,
};

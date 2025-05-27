const AWS = require('aws-sdk');
const logger = require('../config/logger');
const dotenv = require('dotenv');
const path = require('path'); 
const { v4: uuidv4 } = require('uuid'); 

dotenv.config();

// Configure AWS SDK
const s3 = new AWS.S3({
  endpoint: process.env.S3_ENDPOINT,
  accessKeyId: process.env.S3_ACCESS_KEY_ID,
  secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  s3ForcePathStyle: true, 
  signatureVersion: 'v4',
  region: process.env.S3_REGION || 'us-east-1', 
});

const bucketName = process.env.S3_BUCKET_NAME;

/**
 * Uploads a file to S3.
 * @param {Buffer} fileBuffer The buffer of the file to upload.
 * @param {string} originalFilename The original name of the file, used for extension.
 * @param {string} mimeType The MIME type of the file.
 * @returns {Promise<object>} S3 upload result object, including Location (direct S3 URL) and Key.
 * @throws {Error} If bucket name is not defined or upload fails.
 */
async function uploadFile(fileBuffer, originalFilename, mimeType) {
  if (!bucketName) {
    logger.error('S3_BUCKET_NAME is not defined. Cannot upload file.');
    throw new Error('S3_BUCKET_NAME is not defined.');
  }

  const fileExtension = path.extname(originalFilename);
  const uniqueFileName = `${uuidv4()}${fileExtension}`;

  const params = {
    Bucket: bucketName,
    Key: uniqueFileName, 
    Body: fileBuffer,
    ContentType: mimeType,
    ACL: 'public-read', 
  };

  try {
    logger.info(`Uploading to S3: Bucket=${bucketName}, Key=${uniqueFileName}, ContentType=${mimeType}`);
    const data = await s3.upload(params).promise();
    logger.info(`S3 upload successful for key ${uniqueFileName}. S3 Location: ${data.Location}`);
    return data; // Contains Location (direct S3 URL), Key, ETag, etc.
  } catch (error) {
    logger.error(`S3 upload failed for key ${uniqueFileName}:`, {
      message: error.message,
      stack: error.stack,
    });
    throw error; 
  }
}

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
    return true; 
  }

  const objects = keys.map(key => ({ Key: key }));

  const params = {
    Bucket: bucketName,
    Delete: {
      Objects: objects,
      Quiet: false, 
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

/**
 * Applies S3 lifecycle policy to the bucket for auto-deletion.
 * @returns {Promise<boolean>} True if successful, false otherwise.
 */
async function applyS3LifecyclePolicy() {
  if (!bucketName) {
    logger.error('S3_BUCKET_NAME is not defined. Cannot apply lifecycle policy.');
    return false;
  }

  const lifecycleConfig = {
    Rules: [
      {
        ID: 'AutoDeleteOldImages72Hours',
        Status: 'Enabled',
        Filter: {}, // Apply to all objects in the bucket
        Expiration: {
          Days: 3,
        },
        // NoncurrentVersionExpiration: { NoncurrentDays: 3 } // If versioning is enabled
      },
    ],
  };
  const params = {
    Bucket: bucketName,
    LifecycleConfiguration: lifecycleConfig,
  };

  try {
    await s3.putBucketLifecycleConfiguration(params).promise();
    logger.info(`Successfully applied S3 lifecycle configuration to bucket: ${bucketName}`);
    // TODO: Add a note to README.md about this success.
    return true;
  } catch (error) {
    logger.error(`Failed to apply S3 lifecycle configuration to bucket ${bucketName}: ${error.message}`, { error });
    // TODO: Add a note to README.md about this failure and the need for manual setup or cron fallback.
    return false;
  }
}

module.exports = {
  s3, 
  uploadFile,
  deleteObject,
  deleteMultipleObjects,
  applyS3LifecyclePolicy,
};

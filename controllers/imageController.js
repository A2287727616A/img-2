const multer = require('multer');
const logger = require('../config/logger');
const { User } = require('../models'); // Assuming models/index.js exports User
const { logAction, ACTION_TYPES } = require('../services/auditLogService'); // Assuming this path

// Magic numbers for file type validation
const MAGIC_NUMBERS = {
  JPEG: Buffer.from([0xFF, 0xD8, 0xFF]),
  PNG: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  GIF87a: Buffer.from("GIF87a"),
  GIF89a: Buffer.from("GIF89a"),
  WEBP: Buffer.from("RIFF"), // WEBP starts with RIFF, then WEBP in 4 bytes at offset 8
};

const checkMagicNumbers = (buffer) => {
  if (buffer.subarray(0, 3).equals(MAGIC_NUMBERS.JPEG)) return 'image/jpeg';
  if (buffer.subarray(0, 8).equals(MAGIC_NUMBERS.PNG)) return 'image/png';
  if (buffer.subarray(0, 6).equals(MAGIC_NUMBERS.GIF87a)) return 'image/gif';
  if (buffer.subarray(0, 6).equals(MAGIC_NUMBERS.GIF89a)) return 'image/gif';
  if (buffer.subarray(0, 4).equals(MAGIC_NUMBERS.WEBP) && buffer.subarray(8, 12).toString() === 'WEBP') return 'image/webp';
  return null;
};


const uploadImage = async (req, res) => {
  let uploadLimit = 30 * 1024 * 1024; // 30MB default for anonymous/unverified
  let userType = 'anonymous';
  let userIdForLog = null;

  if (req.user) {
    userIdForLog = req.user.id;
    // Assuming req.user is populated by optionalAuth and includes is_verified
    if (req.user.is_verified) {
      uploadLimit = 128 * 1024 * 1024; // 128MB for verified
      userType = 'verified_registered';
    } else {
      userType = 'unverified_registered';
    }
  }

  // File has already been processed by Multer at the route level.
  // Multer's fileFilter and limits (maxUploadLimit) have been applied.

  if (!req.file) {
    // This case might be hit if fileFilter rejected the file, or if no file was sent.
    // Multer usually sends its own error for 'LIMIT_FILE_SIZE' or if fileFilter passes an error.
    // If fileFilter cb(null, false) is called, req.file will be undefined.
    if (req.multerError && req.multerError === 'INVALID_FILE_TYPE') {
         return res.status(400).json({ message: 'Invalid file type. Only JPEG, PNG, GIF, WebP allowed.' });
    }
    return res.status(400).json({ message: 'No image file uploaded or invalid file type.' });
  }

  // Double-check file size against dynamic limit (Multer's limit was max possible)
  if (req.file.size > uploadLimit) {
    logger.warn('File rejected due to dynamic size limit exceeded.', {
      originalName: req.file.originalname,
      size: req.file.size,
      limit: uploadLimit,
      userType,
      userId: userIdForLog,
      ip: req.ip,
    });
    return res.status(413).json({ message: `File too large. Max size for ${userType} is ${uploadLimit / (1024*1024)}MB.` });
  }

  // Basic content sniffing using magic numbers
  const detectedMimeType = checkMagicNumbers(req.file.buffer);
  if (!detectedMimeType || detectedMimeType !== req.file.mimetype) {
    logger.warn('File content validation (magic numbers) failed.', {
        originalName: req.file.originalname,
        declaredMime: req.file.mimetype,
        detectedMime: detectedMimeType || 'unknown',
        userId: userIdForLog,
        ip: req.ip,
    });
    // Consider logging this as a potential security attempt if desired
    // await logAction({ actionType: 'POTENTIAL_MALICIOUS_UPLOAD_MAGIC_NUMBER_MISMATCH', actorIp: req.ip, actorUserId: userIdForLog, details: { originalName: req.file.originalname, declaredMime: req.file.mimetype, detectedMime: detectedMimeType } });
    return res.status(400).json({ message: 'Invalid image content or mismatched file type.' });
  }

  const clientIp = req.ip; // Get client IP
  const { Image } = require('../models'); // Ensure Image model is imported
  const s3Service = require('../services/s3Service'); // Ensure s3Service is imported
  const imageService = require('../services/imageService'); // Import imageService
  const { v4: uuidv4 } = require('uuid'); // Ensure uuid is imported
  const path = require('path'); // Ensure path is imported
  const { generateAlphanumericToken } = require('../utils/token'); // For tempId if still needed, or remove

  logger.info('Image received, starting processing:', {
    originalName: req.file.originalname,
    mimeType: req.file.mimetype,
    size: req.file.size,
    uploaderIp: clientIp,
    userId: userIdForLog,
    userType,
  });

  // Optimization Step
  let optimizedImageData;
  try {
    const optimizationOptions = {
      quality: 80,
      pngCompressionLevel: 9,
      convertToWebP: false, // Set to true to default to WebP, or make it user/admin choice
      removeMetadata: true,
      mimeType: req.file.mimetype
    };
    logger.info(`Optimizing image: ${req.file.originalname}, original size: ${req.file.size}, mime: ${req.file.mimetype}`);
    optimizedImageData = await imageService.optimizeImage(req.file.buffer, optimizationOptions);
    logger.info(`Image optimized: ${req.file.originalname}, new size: ${optimizedImageData.buffer.length}, new mime: ${optimizedImageData.mimeType}`);
  } catch (optimizationError) {
    logger.error('Image optimization failed during upload:', optimizationError);
    return res.status(500).json({ message: 'Image processing failed during optimization.' });
  }

  const fileToUploadBuffer = optimizedImageData.buffer;
  const finalMimeType = optimizedImageData.mimeType;
  const finalSize = optimizedImageData.buffer.length;

  // Update S3 Object Key generation if mimeType changed
  const originalFileExtension = path.extname(req.file.originalname);
  const finalFileExtension = finalMimeType === 'image/webp' ? '.webp' : originalFileExtension;
  const s3ObjectKey = `${uuidv4()}${finalFileExtension}`;

  // 2. Upload to S3
  let s3Response;
  try {
    s3Response = await s3Service.uploadFile(fileToUploadBuffer, s3ObjectKey, finalMimeType);
  } catch (s3Error) {
    logger.error('S3 upload failed:', { 
        s3Error: s3Error.message, 
        stack: s3Error.stack, 
        userId: userIdForLog, 
        ip: clientIp,
        originalName: req.file.originalname
    });
    return res.status(500).json({ message: 'Failed to upload image to storage.' });
  }

  // 3. Prepare Image Data for Database
  const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000); // 72 hours
  const userId = req.user ? req.user.id : null;
  
  const imageData = {
    user_id: userId,
    s3_object_key: s3Response.Key, 
    original_filename: req.file.originalname, // Keep original name
    mime_type: finalMimeType, // Use optimized MIME type
    size_bytes: finalSize, // Use optimized size
    upload_ip: clientIp,
    privacy_level: 'public', 
    expires_at: expiresAt,
    public_url: '', 
  };

  // 4. Create Image Record in Database
  let newImage;
  try {
    newImage = await Image.create(imageData);
  } catch (dbError) {
    logger.error('Failed to save image metadata to database:', {
        dbError: dbError.message,
        stack: dbError.stack,
        s3ObjectKey: s3Response.Key, // Log key for potential manual cleanup
        userId: userIdForLog,
        ip: clientIp
    });
    // Consider deleting from S3 if DB save fails (rollback logic)
    try {
        await s3Service.deleteObject(s3Response.Key);
        logger.info(`S3 object ${s3Response.Key} deleted due to DB save failure.`);
    } catch (s3DeleteError) {
        logger.error(`Failed to delete S3 object ${s3Response.Key} after DB save failure:`, {
            s3DeleteError: s3DeleteError.message,
            stack: s3DeleteError.stack
        });
    }
    return res.status(500).json({ message: 'Failed to save image metadata.' });
  }

  // 5. Construct and Update public_url
  const publicUrl = `${process.env.APP_URL}/i/${newImage.id}`;
  try {
    newImage.public_url = publicUrl;
    await newImage.save();
  } catch (updateError) {
    logger.error('Failed to update image with public_url:', {
        updateError: updateError.message,
        stack: updateError.stack,
        imageId: newImage.id 
    });
    // Image is in S3 and initial record exists. Log and proceed.
    // The public_url might be incorrect, but the image is accessible via S3 URL.
  }

  // 6. Audit Log (Placeholder - to be added properly later)
  // await logAction({ 
  //   actorUserId: userId, 
  //   actorIp: clientIp, 
  //   actionType: ACTION_TYPES.IMAGE_UPLOAD_SUCCESS, // Assuming an ACTION_TYPE for this
  //   targetResourceId: newImage.id.toString(), 
  //   details: { filename: newImage.original_filename, s3_key: newImage.s3_object_key, public_url: newImage.public_url } 
  // });

  // 7. Respond to Client
  res.status(201).json({
    message: 'Image uploaded successfully!',
    image_id: newImage.id,
    public_url: newImage.public_url,
    s3_url: s3Response.Location, // Direct S3 URL
    original_filename: newImage.original_filename,
    mime_type: newImage.mime_type,
    size_bytes: newImage.size_bytes,
    expires_at: newImage.expires_at
  });
};

module.exports = {
  uploadImage,
};

// Ensure these imports are at the top of the file.
// Some might already be there from previous steps.
// const { Image } = require('../models');
// const s3Service = require('../services/s3Service');
// const imageService = require('../services/imageService');
// const { v4: uuidv4 } = require('uuid');
// const path = require('path');
// const { generateAlphanumericToken } = require('../utils/token'); // if tempId logic was kept

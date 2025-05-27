const sharp = require('sharp');
const logger = require('../config/logger');

/**
 * Optimizes an image buffer using Sharp.
 *
 * @param {Buffer} inputBuffer The buffer of the original uploaded image.
 * @param {object} [options={}] An object that can contain optimization options.
 * @param {number} [options.quality=80] General quality for JPEG/WebP (1-100).
 * @param {number} [options.pngCompressionLevel=9] Compression level for PNG (0-9 for Sharp).
 * @param {boolean} [options.convertToWebP=false] Whether to attempt conversion to WebP.
 * @param {boolean} [options.removeMetadata=true] Whether to strip EXIF and other metadata.
 * @param {string} options.mimeType The original MIME type of the image (e.g., 'image/jpeg', 'image/png').
 * @returns {Promise<{buffer: Buffer, mimeType: string}>} An object containing the optimized buffer and the final MIME type.
 * @throws {Error} If image optimization fails.
 */
async function optimizeImage(inputBuffer, options = {}) {
  if (!options.mimeType) {
    logger.error('optimizeImage called without mimeType option.');
    throw new Error('mimeType is required in options for optimizeImage.');
  }

  let imageProcessor = sharp(inputBuffer);
  const currentMimeType = options.mimeType;
  let finalMimeType = currentMimeType;

  // 1. Metadata Removal (defaulted to true)
  if (options.removeMetadata !== false) {
    imageProcessor = imageProcessor.withMetadata({ 
        exif: false, 
        icc: false, 
        iptc: false, 
        xmp: false,
        // Keep orientation to prevent images from rotating unexpectedly
        // orientation: true // This is default, explicitly stating if we want to keep it
    });
  }

  // 2. Format-Specific Optimization & WebP Conversion
  const quality = options.quality || 80; // Default quality for JPEG/WebP
  const pngCompressionLevel = options.pngCompressionLevel !== undefined ? options.pngCompressionLevel : 9; // Default PNG compression

  if (options.convertToWebP) {
    logger.debug(`Optimizing and converting to WebP: quality ${quality}`, { originalMime: currentMimeType });
    imageProcessor = imageProcessor.webp({ quality: quality });
    finalMimeType = 'image/webp';
  } else {
    logger.debug(`Optimizing for original format: ${currentMimeType}`);
    if (currentMimeType === 'image/jpeg') {
      imageProcessor = imageProcessor.jpeg({ 
          quality: quality, 
          progressive: true, 
          optimizeScans: true 
      });
    } else if (currentMimeType === 'image/png') {
      // Sharp's .png() quality option (0-100) is different from compressionLevel (0-9)
      // We'll use compressionLevel for finer control as requested by task.
      // The quality option for png in sharp relates to quantisation, not zlib compression.
      imageProcessor = imageProcessor.png({ 
          compressionLevel: pngCompressionLevel, 
          adaptiveFiltering: true,
          // quality: quality, // if we prefer to use quantisation based quality
      });
    } else if (currentMimeType === 'image/gif') {
      // GIF optimization with Sharp can be limited.
      // It might involve setting options like 'effort' or 'loop' if needed.
      // Basic pass-through or simple optimization:
      imageProcessor = imageProcessor.gif({ effort: 10 }); // effort 1-10, higher is more effort
    } else if (currentMimeType === 'image/webp') {
      // If it's already WebP and not converting, re-compress with specified quality
      imageProcessor = imageProcessor.webp({ quality: quality });
    }
    // Other types are passed through without specific optimization for now
  }

  // 3. Get Optimized Buffer
  try {
    const optimizedBuffer = await imageProcessor.toBuffer();
    logger.info('Image optimization successful.', { 
        originalSize: inputBuffer.length, 
        optimizedSize: optimizedBuffer.length, 
        originalMime: currentMimeType,
        finalMime: finalMimeType 
    });
    return { buffer: optimizedBuffer, mimeType: finalMimeType };
  } catch (error) {
    logger.error('Image optimization failed during toBuffer():', { 
        message: error.message, 
        stack: error.stack,
        optionsUsed: options
    });
    throw new Error('Failed to optimize image.');
  }
}

module.exports = {
  optimizeImage,
};

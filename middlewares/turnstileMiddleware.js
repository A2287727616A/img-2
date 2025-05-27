const axios = require('axios');
const logger = require('../config/logger');
const dotenv = require('dotenv');

dotenv.config();

const verifyTurnstile = async (req, res, next) => {
  // Check if Turnstile verification should be skipped for development
  if (
    process.env.NODE_ENV === 'development' &&
    process.env.SKIP_TURNSTILE_VERIFICATION === 'true'
  ) {
    logger.warn('Cloudflare Turnstile verification SKIPPED due to SKIP_TURNSTILE_VERIFICATION=true in development mode.', { path: req.path, ip: req.ip });
    return next();
  }

  const turnstileToken = req.body['cf-turnstile-response'] || req.query['cf-turnstile-response'];

  if (!turnstileToken) {
    logger.warn('Cloudflare Turnstile token missing.', { path: req.path, ip: req.ip });
    return res.status(403).json({ message: 'Cloudflare Turnstile token is missing. Please complete the CAPTCHA challenge.' });
  }

  try {
    const response = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        secret: process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY,
        response: turnstileToken,
        remoteip: req.ip, // Optional, but recommended
      },
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000, // Timeout after 5 seconds
      }
    );

    if (response.data && response.data.success) {
      logger.info('Cloudflare Turnstile verification successful.', { path: req.path, ip: req.ip, hostname: response.data.hostname, action: response.data.action, cdata: response.data.cdata });
      next();
    } else {
      logger.warn('Cloudflare Turnstile verification failed.', {
        path: req.path,
        ip: req.ip,
        'error-codes': response.data ? response.data['error-codes'] : 'N/A',
        challenge_ts: response.data ? response.data.challenge_ts : 'N/A',
        hostname: response.data ? response.data.hostname : 'N/A',
      });
      return res.status(403).json({ message: 'Failed Cloudflare Turnstile verification. Please try again.' });
    }
  } catch (error) {
    logger.error('Error during Cloudflare Turnstile verification process:', {
      path: req.path,
      ip: req.ip,
      message: error.message,
      stack: error.stack,
      isAxiosError: error.isAxiosError,
      axiosCode: error.code, // e.g., ECONNABORTED for timeout
    });
    // Check if it's a timeout
    if (error.isAxiosError && error.code === 'ECONNABORTED') {
        return res.status(504).json({ message: 'CAPTCHA verification timed out. Please try again.' });
    }
    return res.status(500).json({ message: 'Error verifying CAPTCHA. Please try again later.' });
  }
};

module.exports = {
  verifyTurnstile,
};

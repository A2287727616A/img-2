const jwt = require('jsonwebtoken');
const { User } = require('../models'); // Assuming models/index.js exports User
const logger = require('../config/logger');
const dotenv = require('dotenv');

dotenv.config();

const isAuthenticated = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn('Authentication attempt with missing or malformed token.', { ip: req.ip });
    return res.status(401).json({ message: 'Authentication token is required.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Optional: Check if user still exists or is active, using jti to check session validity
    // For this task, we'll keep it simple and just use decoded id.
    // const user = await User.findByPk(decoded.id);
    // if (!user || user.is_banned) { // Or check against a session revocation list using decoded.jti
    //   logger.warn('Authentication attempt with token for non-existent or banned user.', { userId: decoded.id, ip: req.ip });
    //   return res.status(401).json({ message: 'Invalid token or user not authorized.' });
    // }

    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      // jti: decoded.jti // if you plan to use it for session management
    };
    logger.debug('User authenticated successfully.', { userId: req.user.id, path: req.path });
    next();
  } catch (error) {
    logger.warn('Invalid or expired token.', {
      errorName: error.name,
      errorMessage: error.message,
      ip: req.ip,
    });
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired.' });
    }
    return res.status(401).json({ message: 'Invalid token.' });
  }
};

const isAdmin = (req, res, next) => {
    if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'super_admin')) {
        logger.warn('Admin authorization denied.', { userId: req.user ? req.user.id : 'N/A', role: req.user ? req.user.role : 'N/A', ip: req.ip, path: req.path });
        return res.status(403).json({ message: 'Forbidden: Access is restricted to administrators.' });
    }
    next();
};

const isSuperAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'super_admin') {
        logger.warn('Super admin authorization denied.', { userId: req.user ? req.user.id : 'N/A', role: req.user ? req.user.role : 'N/A', ip: req.ip, path: req.path });
        return res.status(403).json({ message: 'Forbidden: Access is restricted to super administrators.' });
    }
    next();
};


module.exports = {
  isAuthenticated,
  isAdmin,
  isSuperAdmin,
};

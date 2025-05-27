const express = require('express');
const dotenv = require('dotenv');
const logger = require('./config/logger');
const db = require('./models'); // Import the db object from models/index.js

// Load environment variables
dotenv.config();

const app = express();

// Trust proxy for accurate IP (e.g., if behind Nginx, Heroku, Cloudflare)
app.set('trust proxy', 1); // Adjust if needed, e.g., number of proxies

// Middleware to parse JSON bodies
app.use(express.json());
// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));


// Import routes
const authRoutes = require('./routes/authRoutes');

// Mount routers
app.use('/api/auth', authRoutes);
const userRoutes = require('./routes/userRoutes'); // Assuming this exists
app.use('/api/user', userRoutes); // Assuming this exists
const imageRoutes = require('./routes/imageRoutes');
app.use('/api/images', imageRoutes);


// Basic route
app.get('/', (req, res) => {
  res.json({ message: "Welcome to Memory Echoes API" });
});

const PORT = process.env.PORT || 1190;

const { createDefaultSuperAdmin } = require('./services/setupService');

const { createDefaultSuperAdmin } = require('./services/setupService');
const { initializeCronJobs } = require('./services/cronJobs');
const { applyS3LifecyclePolicy } = require('./services/s3Service'); // Import S3 lifecycle setup

// Sync database and start server
async function startServer() {
  if (process.env.NODE_ENV !== 'test') {
    try {
      await db.sequelize.authenticate();
      logger.info('Database connection has been established successfully.');

      const syncOptions = { alter: process.env.NODE_ENV === 'development' };
      await db.sequelize.sync(syncOptions);
      logger.info(`All models were synchronized successfully. Sync options: ${JSON.stringify(syncOptions)}`);

      // Create default super admin after successful sync
      await createDefaultSuperAdmin();

      // Initialize cron jobs
      initializeCronJobs();

      // Attempt to apply S3 lifecycle policy
      await applyS3LifecyclePolicy();

    } catch (error) {
      logger.error('Error during server startup (DB sync, admin creation, crons, or S3 lifecycle):', error);
      // process.exit(1); // Optionally exit if critical setup fails
    }
  }

  app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
    logger.info(`App URL: ${process.env.APP_URL || `http://localhost:${PORT}`}`);
  });
}

startServer();

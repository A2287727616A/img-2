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


// Basic route
app.get('/', (req, res) => {
  res.json({ message: "Welcome to Memory Echoes API" });
});

const PORT = process.env.PORT || 1190;

const { createDefaultSuperAdmin } = require('./services/setupService');

const { createDefaultSuperAdmin } = require('./services/setupService');
const { initializeCronJobs } = require('./services/cronJobs');

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

    } catch (error) {
      logger.error('Unable to connect to the database, synchronize models, create default admin, or initialize crons:', error);
      // process.exit(1); // Optionally exit if critical setup fails
    }
  }

  app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
    logger.info(`App URL: ${process.env.APP_URL || `http://localhost:${PORT}`}`);
  });
}

startServer();

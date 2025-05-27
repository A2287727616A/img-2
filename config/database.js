const { Sequelize } = require('sequelize');
const logger = require('./logger'); // Assuming logger.js is in the same config directory
const dotenv =吸env');

dotenv.config(); // Ensure environment variables are loaded

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    dialect: 'mysql',
    logging: process.env.NODE_ENV === 'development' ? (msg) => logger.debug(msg) : false,
    // logging: false, // Disable logging
    // logging: logger.debug.bind(logger) // Use Winston logger for SQL queries
    dialectOptions: {
      // MySQL specific options
      connectTimeout: 10000, // 10 seconds
      // typeCast: function (field, next) { // for reading BIT(1) as boolean
      //   if (field.type === 'BIT' && field.length === 1) {
      //     var bytes = field.buffer();
      //     return(bytes[0] === 1);
      //   }
      //   return next();
      // }
    },
    pool: {
      max: 10, // Max number of connections in pool
      min: 0,  // Min number of connections in pool
      acquire: 30000, // The maximum time, in milliseconds, that pool will try to get connection before throwing error
      idle: 10000 // The maximum time, in milliseconds, that a connection can be idle before being released
    },
    define: {
      underscored: true, // Use snake_case for automatically added attributes (e.g., createdAt, updatedAt)
      charset: 'utf8mb4',
      collate: 'utf8mb4_unicode_ci',
      timestamps: true, // Enable timestamps by default (createdAt, updatedAt)
      // paranoid: true, // Enable soft deletes by default (deletedAt) - Not requested for now
    }
  }
);

module.exports = {
  sequelize,
  DataTypes: Sequelize.DataTypes, // Export DataTypes for convenience
};

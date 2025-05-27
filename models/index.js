const { sequelize, DataTypes } = require('../config/database'); // Adjusted to directly use exported sequelize and DataTypes
const logger = require('../config/logger');

const db = {};

db.Sequelize = Sequelize; // The Sequelize library itself
db.sequelize = sequelize; // The sequelize instance

// Import models
// Make sure the path and the function signature match how you've defined your models
db.User = require('./User')(sequelize, DataTypes);
db.UserIp = require('./UserIp')(sequelize, DataTypes);
db.Image = require('./Image')(sequelize, DataTypes);
db.StatsCounter = require('./StatsCounter')(sequelize, DataTypes);
db.AuditLog = require('./AuditLog')(sequelize, DataTypes);
db.ImageReport = require('./ImageReport')(sequelize, DataTypes);
db.Announcement = require('./Announcement')(sequelize, DataTypes);
db.ApiKey = require('./ApiKey')(sequelize, DataTypes);
db.Watermark = require('./Watermark')(sequelize, DataTypes);
db.Collection = require('./Collection')(sequelize, DataTypes);
db.CollectionImage = require('./CollectionImage')(sequelize, DataTypes);

// Define associations
// This pattern calls the .associate function on each model if it exists.
Object.keys(db).forEach(modelName => {
  if (db[modelName] && db[modelName].associate) {
    logger.info(`Associating model: ${modelName}`);
    db[modelName].associate(db);
  } else if (modelName !== 'Sequelize' && modelName !== 'sequelize') {
    // Log if a model file is imported but doesn't have an associate function (and isn't Sequelize/sequelize itself)
    // logger.warn(`Model ${modelName} does not have an associate function.`);
  }
});

// Test connection and sync database (optional here, could be in server.js)
// async function testConnectionAndSync() {
//   try {
//     await sequelize.authenticate();
//     logger.info('Database connection has been established successfully.');
//     // Sync all models
//     // In development, you might use: await sequelize.sync({ force: true }); to drop and recreate tables
//     // For production, use migrations. For development with data persistence:
//     await sequelize.sync({ alter: process.env.NODE_ENV === 'development' ? true : false }); // alter:true can be risky.
//     // await sequelize.sync({ alter: true }); // Or just true if you understand the risks
//     logger.info("All models were synchronized successfully.");
//   } catch (error) {
//     logger.error('Unable to connect to the database or synchronize models:', error);
//   }
// }

// if (process.env.NODE_ENV !== 'test') { // Avoid sync during tests if using a separate test DB setup
//   testConnectionAndSync();
// }


module.exports = db;

const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Or use crypto for hashing if preferred

module.exports = (sequelize, DataTypes) => {
  const ApiKey = sequelize.define('ApiKey', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'users', // Name of the target table
        key: 'id',
      },
      onDelete: 'CASCADE',
    },
    key_name: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    api_key_hash: { // Store a hash of the API key, not the key itself
      type: DataTypes.STRING(255),
      unique: true,
      allowNull: false,
    },
    last_used_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    expires_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    // created_at and updated_at are managed by Sequelize
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'api_keys',
    hooks: {
      // No automatic hashing hook here for api_key_hash because the actual key is generated
      // by the application, shown to the user once, and then hashed for storage.
      // The hashing should occur in the service/controller layer before saving.
    }
  });

  ApiKey.associate = (models) => {
    ApiKey.belongsTo(models.User, {
      foreignKey: 'user_id',
      as: 'user',
    });
  };

  // Instance method to compare a provided key with the stored hash
  // This would typically be called in an authentication middleware or service
  ApiKey.prototype.isValidKey = async function(providedKey) {
    // This depends on how you hash the key. If using bcrypt:
    return await bcrypt.compare(providedKey, this.api_key_hash);
    // If using a simple SHA256 hash (not recommended for passwords, but sometimes used for API keys):
    // const hashOfProvidedKey = crypto.createHash('sha256').update(providedKey).digest('hex');
    // return this.api_key_hash === hashOfProvidedKey;
  };

  // Static method to hash a key before saving (if you want it here, otherwise in service)
  // ApiKey.hashKey = async (apiKey) => {
  //   const salt = await bcrypt.genSalt(10);
  //   return await bcrypt.hash(apiKey, salt);
  // };

  return ApiKey;
};

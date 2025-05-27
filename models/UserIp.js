module.exports = (sequelize, DataTypes) => {
  const UserIp = sequelize.define('UserIp', {
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
    ip_address: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    user_agent: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    device_name: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    last_login_at: {
      type: DataTypes.DATE, // Sequelize uses DATE for TIMESTAMP
      defaultValue: DataTypes.NOW,
    },
    is_known_device: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    session_id: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
    },
    is_active_session: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    last_activity_at: {
      type: DataTypes.DATE, // Sequelize uses DATE for TIMESTAMP
      defaultValue: DataTypes.NOW,
      // MySQL specific: ON UPDATE CURRENT_TIMESTAMP - Sequelize handles this via hooks or application logic if needed
    },
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'user_ips',
    // For last_activity_at to auto-update, you might need a hook or manage it at application level
    // Sequelize doesn't directly translate ON UPDATE CURRENT_TIMESTAMP for all dialects
    hooks: {
      beforeUpdate: (instance) => {
        if (instance.changed('is_active_session') || !instance.last_activity_at) {
          // Only update last_activity_at if session status changes or it's the first update
          // More typically, this would be updated on any significant user activity.
          instance.last_activity_at = new Date();
        }
      }
    }
  });

  UserIp.associate = (models) => {
    UserIp.belongsTo(models.User, {
      foreignKey: 'user_id',
      as: 'user',
    });
  };

  return UserIp;
};

const bcrypt = require('bcrypt');

module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    email: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
      validate: {
        isEmail: true,
      },
    },
    password_hash: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    role: {
      type: DataTypes.ENUM('user', 'admin', 'super_admin'),
      defaultValue: 'user',
    },
    is_verified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    verification_token: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    verification_token_expires_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    reset_password_token: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: true,
    },
    reset_password_token_expires_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    login_otp_token: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    login_otp_token_expires_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    pending_email: {
      type: DataTypes.STRING,
      allowNull: true,
      validate: {
        isEmail: true,
      },
    },
    email_change_token: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: true,
    },
    email_change_token_expires_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    email_change_freeze_until: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    two_factor_secret: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    two_factor_enabled: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    two_factor_recovery_codes: {
      type: DataTypes.TEXT, // Storing as JSON string, consider DataTypes.JSON if db supports
      allowNull: true,
      get() {
        const value = this.getDataValue('two_factor_recovery_codes');
        return value ? JSON.parse(value) : null;
      },
      set(value) {
        this.setDataValue('two_factor_recovery_codes', value ? JSON.stringify(value) : null);
      }
    },
    failed_login_attempts: {
      type: DataTypes.TINYINT,
      defaultValue: 0,
    },
    last_failed_login_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    account_locked_until: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    account_deletion_requested_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    account_deletion_confirmation_token: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: true,
    },
    account_deletion_token_expires_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    is_banned: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    ban_reason: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    banned_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    auto_banned_at: {
        type: DataTypes.DATE,
        allowNull: true,
    },
    auto_ban_reason: {
        type: DataTypes.TEXT,
        allowNull: true,
    },
    unban_request_token: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: true,
    },
    unban_request_token_expires_at: {
        type: DataTypes.DATE,
        allowNull: true,
    },
    default_image_privacy: {
      type: DataTypes.ENUM('public', 'unlisted', 'private'),
      defaultValue: 'public',
    },
    default_watermark_id: { // Foreign key, will be defined in association
      type: DataTypes.INTEGER,
      allowNull: true,
    },
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'users',
    hooks: {
      beforeCreate: async (user) => {
        if (user.password_hash) {
          const salt = await bcrypt.genSalt(10);
          user.password_hash = await bcrypt.hash(user.password_hash, salt);
        }
      },
      beforeUpdate: async (user) => {
        if (user.changed('password_hash') && user.password_hash) {
          const salt = await bcrypt.genSalt(10);
          user.password_hash = await bcrypt.hash(user.password_hash, salt);
        }
      },
    },
    // Default scope to exclude sensitive fields
    defaultScope: {
      attributes: {
        exclude: [
          'password_hash', 'verification_token', 'reset_password_token',
          'login_otp_token', 'email_change_token', 'two_factor_secret',
          'two_factor_recovery_codes', 'account_deletion_confirmation_token',
          'unban_request_token'
        ]
      }
    },
    scopes: {
      withSensitiveInfo: {
        attributes: { include: undefined } // Includes all attributes
      }
    }
  });

  User.prototype.validPassword = async function(password) {
    return await bcrypt.compare(password, this.password_hash);
  };

  User.associate = (models) => {
    // User has many UserIps
    User.hasMany(models.UserIp, {
      foreignKey: 'user_id',
      as: 'ips',
      onDelete: 'CASCADE',
    });

    // User has many Images
    User.hasMany(models.Image, {
      foreignKey: 'user_id',
      as: 'images',
      onDelete: 'SET NULL', // Or 'CASCADE' if images should be deleted with user
    });

    // User has many ApiKeys
    User.hasMany(models.ApiKey, {
      foreignKey: 'user_id',
      as: 'apiKeys',
      onDelete: 'CASCADE',
    });

    // User has many Watermarks (non-global ones)
    User.hasMany(models.Watermark, {
      foreignKey: 'user_id',
      as: 'watermarks',
      scope: { is_global: false }, // Only user-specific watermarks
      onDelete: 'CASCADE',
    });

    // User has a default Watermark
    User.belongsTo(models.Watermark, {
      foreignKey: 'default_watermark_id',
      as: 'defaultWatermark',
      constraints: false, // Can be null or point to a global watermark
    });

    // User has many Collections
    User.hasMany(models.Collection, {
      foreignKey: 'user_id',
      as: 'collections',
      onDelete: 'CASCADE',
    });

    // User as a reporter for ImageReports
    User.hasMany(models.ImageReport, {
      foreignKey: 'reporter_user_id',
      as: 'reportedImages',
      onDelete: 'SET NULL',
    });

    // User as an admin reviewer for ImageReports
    User.hasMany(models.ImageReport, {
      foreignKey: 'reviewed_by_admin_id',
      as: 'reviewedImageReports',
      onDelete: 'SET NULL',
    });

    // User as creator of Announcements
    User.hasMany(models.Announcement, {
      foreignKey: 'created_by_admin_id',
      as: 'createdAnnouncements',
      onDelete: 'CASCADE', // Or SET NULL if you want to keep announcements from deleted admins
    });

    // User as actor in AuditLogs
    User.hasMany(models.AuditLog, {
      foreignKey: 'actor_user_id',
      as: 'actionsPerformed',
      onDelete: 'SET NULL',
    });

    // User as target in AuditLogs
    User.hasMany(models.AuditLog, {
      foreignKey: 'target_user_id',
      as: 'targetedInActions',
      onDelete: 'SET NULL',
    });
  };

  return User;
};

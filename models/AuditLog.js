module.exports = (sequelize, DataTypes) => {
  const AuditLog = sequelize.define('AuditLog', {
    id: {
      type: DataTypes.BIGINT,
      primaryKey: true,
      autoIncrement: true,
    },
    timestamp: {
      type: DataTypes.DATE, // Sequelize's DATE is DATETIME for MySQL
      defaultValue: DataTypes.NOW,
    },
    actor_user_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'users',
        key: 'id',
      },
      onDelete: 'SET NULL',
    },
    actor_ip: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    action_type: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    target_user_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'users',
        key: 'id',
      },
      onDelete: 'SET NULL',
    },
    target_resource_id: {
      type: DataTypes.STRING, // Can be ID of an image, collection, etc.
      allowNull: true,
    },
    details: {
      type: DataTypes.TEXT, // Using TEXT for flexibility, can store JSON string
      allowNull: true,
      get() {
        const value = this.getDataValue('details');
        try {
          return value ? JSON.parse(value) : null;
        } catch (e) {
          return value; // Return as plain text if not valid JSON
        }
      },
      set(value) {
        if (typeof value === 'object' && value !== null) {
          this.setDataValue('details', JSON.stringify(value));
        } else {
          this.setDataValue('details', value);
        }
      }
    },
    // 'createdAt' will be automatically managed by Sequelize
    // 'updatedAt' will be automatically managed by Sequelize
  }, {
    timestamps: true, // This will add createdAt and updatedAt
    updatedAt: false, // We only need createdAt for Audit Logs
    createdAt: 'timestamp', // Alias createdAt to timestamp to match schema, but this is already default for `timestamp` field.
                           // If we want 'timestamp' to be the only creation field and 'createdAt' to be something else or disabled.
                           // Let's stick to Sequelize defaults + custom 'timestamp' field for clarity.
                           // The task asks for 'timestamp' and 'created_at'.
                           // Sequelize will create 'created_at' and 'updated_at'.
                           // If 'timestamp' is meant to be the creation time, we can use `defaultValue: DataTypes.NOW` for it.
                           // And set `createdAt: 'created_at'` (which is default) or a different name if needed.
                           // The request is: `timestamp` (DEFAULT CURRENT_TIMESTAMP) and `created_at` (DEFAULT CURRENT_TIMESTAMP)
                           // This is redundant. Let's make `timestamp` the main field and disable separate `createdAt`/`updatedAt`
                           // by setting `timestamps: false` and manually defining `timestamp`.
                           // Or, let Sequelize manage `createdAt` and use it as the audit timestamp.
                           // Given "created_at (TIMESTAMP, DEFAULT CURRENT_TIMESTAMP)" in task.txt,
                           // it seems `timestamps: true` with `updatedAt: false` is the way.
                           // The `timestamp` field in the model will be the `createdAt` from Sequelize.
                           // Let's rename the Sequelize `createdAt` to `timestamp` to match the spec.
    // Correct approach for "timestamp (DEFAULT CURRENT_TIMESTAMP)" and "created_at (DEFAULT CURRENT_TIMESTAMP)":
    // The `timestamp` field defined above with `defaultValue: DataTypes.NOW` handles the first.
    // Sequelize's `timestamps: true` will add `created_at` and `updated_at`.
    // We set `updatedAt: false` as per task. `created_at` will be generated.
    // So, we will have both `timestamp` (our custom field) and `created_at` (by Sequelize).
    // This seems to match the request.
    underscored: true,
    tableName: 'audit_logs',
  });

  AuditLog.associate = (models) => {
    AuditLog.belongsTo(models.User, {
      foreignKey: 'actor_user_id',
      as: 'actorUser', // Alias for the association
    });
    AuditLog.belongsTo(models.User, {
      foreignKey: 'target_user_id',
      as: 'targetUser', // Alias for the association
    });
  };

  return AuditLog;
};

module.exports = (sequelize, DataTypes) => {
  const ImageReport = sequelize.define('ImageReport', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    image_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'images', // Name of the target table
        key: 'id',
      },
      onDelete: 'CASCADE',
    },
    reporter_user_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'users',
        key: 'id',
      },
      onDelete: 'SET NULL',
    },
    reporter_ip: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    report_reason: {
      type: DataTypes.ENUM('copyright', 'illegal_content', 'spam', 'nsfw', 'other'),
      allowNull: false,
    },
    report_notes: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    status: {
      type: DataTypes.ENUM('pending_review', 'resolved_no_action', 'resolved_image_deleted', 'resolved_user_warned', 'resolved_user_banned'),
      defaultValue: 'pending_review',
    },
    reported_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
    },
    reviewed_by_admin_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'users',
        key: 'id',
      },
      onDelete: 'SET NULL',
    },
    reviewed_at: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    // created_at and updated_at are managed by Sequelize
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'image_reports',
    // If 'reported_at' should be strictly 'createdAt', then:
    // createdAt: 'reported_at',
    // updatedAt: 'updated_at', // or false if no updated_at needed
    // However, the schema implies 'reported_at' is distinct from 'created_at'/'updated_at'
    // So we keep `timestamps: true` for standard created_at/updated_at and define 'reported_at' separately.
  });

  ImageReport.associate = (models) => {
    ImageReport.belongsTo(models.Image, {
      foreignKey: 'image_id',
      as: 'image',
    });
    ImageReport.belongsTo(models.User, {
      foreignKey: 'reporter_user_id',
      as: 'reporter',
    });
    ImageReport.belongsTo(models.User, {
      foreignKey: 'reviewed_by_admin_id',
      as: 'reviewer',
    });
  };

  return ImageReport;
};

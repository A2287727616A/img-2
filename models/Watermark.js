module.exports = (sequelize, DataTypes) => {
  const Watermark = sequelize.define('Watermark', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: true, // NULL for global watermarks
      references: {
        model: 'users',
        key: 'id',
      },
      onDelete: 'CASCADE', // If user is deleted, their specific watermarks are deleted
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    type: {
      type: DataTypes.ENUM('text', 'image'),
      allowNull: false,
    },
    text_content: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    text_font: {
      type: DataTypes.STRING(100),
      allowNull: true,
    },
    text_size: {
      type: DataTypes.INTEGER,
      allowNull: true,
    },
    text_color: {
      type: DataTypes.STRING(7), // e.g., #RRGGBB
      allowNull: true,
      validate: {
        is: /^#[0-9A-Fa-f]{6}$/i, // Basic hex color validation
      },
    },
    image_s3_key: { // S3 key for the watermark image
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    position: {
      type: DataTypes.ENUM('top_left', 'top_right', 'bottom_left', 'bottom_right', 'center', 'tile'),
      defaultValue: 'bottom_right',
    },
    opacity: {
      type: DataTypes.FLOAT,
      defaultValue: 1.0,
      validate: {
        min: 0.0,
        max: 1.0,
      },
    },
    is_global: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    // created_at and updated_at are managed by Sequelize
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'watermarks',
    indexes: [
      {
        fields: ['user_id'], // Index for user-specific watermarks
      },
      {
        fields: ['is_global'], // Index for global watermarks
      }
    ]
  });

  Watermark.associate = (models) => {
    Watermark.belongsTo(models.User, {
      foreignKey: 'user_id',
      as: 'user', // A user can have many watermarks
      allowNull: true, // Required for global watermarks
    });

    // A watermark can be applied to many images
    Watermark.hasMany(models.Image, {
      foreignKey: 'applied_watermark_id',
      as: 'appliedToImages',
    });

    // A watermark can be a default for many users
    Watermark.hasMany(models.User, {
        foreignKey: 'default_watermark_id',
        as: 'defaultForUsers'
    });
  };

  return Watermark;
};

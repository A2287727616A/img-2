module.exports = (sequelize, DataTypes) => {
  const Image = sequelize.define('Image', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    user_id: {
      type: DataTypes.INTEGER,
      allowNull: true, // Allow anonymous uploads
      references: {
        model: 'users',
        key: 'id',
      },
      onDelete: 'SET NULL',
    },
    s3_object_key: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: false,
    },
    original_filename: {
      type: DataTypes.STRING,
      allowNull: true, // Can be null if not provided or for API uploads
    },
    mime_type: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    size_bytes: {
      type: DataTypes.BIGINT,
      allowNull: true,
    },
    upload_ip: {
      type: DataTypes.STRING,
      allowNull: true,
    },
    public_url: {
      type: DataTypes.STRING,
      allowNull: false, // This should always be generated
    },
    privacy_level: {
      type: DataTypes.ENUM('public', 'unlisted', 'private'),
      defaultValue: 'public',
    },
    applied_watermark_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'watermarks',
        key: 'id',
      },
      onDelete: 'SET NULL',
    },
    uploaded_at: {
      type: DataTypes.DATE, // Sequelize uses DATE for TIMESTAMP
      defaultValue: DataTypes.NOW,
    },
    expires_at: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    // created_at and updated_at are managed by Sequelize via timestamps: true
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'images',
    indexes: [
      {
        fields: ['user_id'],
      },
      {
        fields: ['s3_object_key'],
      },
      {
        fields: ['expires_at'],
      }
    ]
  });

  Image.associate = (models) => {
    Image.belongsTo(models.User, {
      foreignKey: 'user_id',
      as: 'user',
      allowNull: true, // Consistent with field definition
    });

    Image.belongsTo(models.Watermark, {
      foreignKey: 'applied_watermark_id',
      as: 'appliedWatermark',
      allowNull: true,
    });

    Image.hasMany(models.ImageReport, {
      foreignKey: 'image_id',
      as: 'reports',
      onDelete: 'CASCADE',
    });

    Image.belongsToMany(models.Collection, {
      through: models.CollectionImage,
      foreignKey: 'image_id',
      otherKey: 'collection_id',
      as: 'collections',
    });
  };

  return Image;
};

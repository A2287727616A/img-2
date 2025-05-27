module.exports = (sequelize, DataTypes) => {
  const CollectionImage = sequelize.define('CollectionImage', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    collection_id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'collections', // Name of the target table
        key: 'id',
      },
      onDelete: 'CASCADE',
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
    added_at: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
    },
    // created_at and updated_at are managed by Sequelize
  }, {
    timestamps: true, // This will add createdAt and updatedAt
    // If 'added_at' should be the 'createdAt' field:
    // createdAt: 'added_at',
    // updatedAt: false, // Or some other field name if updates are tracked differently
    // For this schema, 'added_at' is distinct, so standard timestamps are fine.
    underscored: true,
    tableName: 'collection_images',
    indexes: [
      {
        unique: true,
        fields: ['collection_id', 'image_id'],
      },
    ],
  });

  CollectionImage.associate = (models) => {
    CollectionImage.belongsTo(models.Collection, {
      foreignKey: 'collection_id',
      as: 'collection',
    });
    CollectionImage.belongsTo(models.Image, {
      foreignKey: 'image_id',
      as: 'image',
    });
  };

  return CollectionImage;
};

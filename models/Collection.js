module.exports = (sequelize, DataTypes) => {
  const Collection = sequelize.define('Collection', {
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
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    privacy_level: {
      type: DataTypes.ENUM('public', 'unlisted', 'private'),
      defaultValue: 'private',
    },
    // created_at and updated_at are managed by Sequelize
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'collections',
  });

  Collection.associate = (models) => {
    Collection.belongsTo(models.User, {
      foreignKey: 'user_id',
      as: 'user',
    });

    Collection.belongsToMany(models.Image, {
      through: models.CollectionImage,
      foreignKey: 'collection_id',
      otherKey: 'image_id',
      as: 'images',
    });
  };

  return Collection;
};

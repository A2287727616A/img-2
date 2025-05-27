module.exports = (sequelize, DataTypes) => {
  const Announcement = sequelize.define('Announcement', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    title: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    content: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    level: {
      type: DataTypes.ENUM('info', 'warning', 'critical'),
      defaultValue: 'info',
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    show_to_logged_in_users_only: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    show_to_admin_only: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    created_by_admin_id: {
      type: DataTypes.INTEGER,
      allowNull: false, // Assuming an announcement must be created by an admin
      references: {
        model: 'users', // Name of the target table
        key: 'id',
      },
      onDelete: 'CASCADE', // Or 'SET NULL' if announcements should persist if admin user is deleted
    },
    // created_at and updated_at are managed by Sequelize
  }, {
    timestamps: true,
    underscored: true,
    tableName: 'announcements',
  });

  Announcement.associate = (models) => {
    Announcement.belongsTo(models.User, {
      foreignKey: 'created_by_admin_id',
      as: 'creator', // Alias for the admin who created the announcement
    });
  };

  return Announcement;
};

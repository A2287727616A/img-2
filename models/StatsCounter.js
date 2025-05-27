module.exports = (sequelize, DataTypes) => {
  const StatsCounter = sequelize.define('StatsCounter', {
    counter_name: {
      type: DataTypes.STRING,
      primaryKey: true,
    },
    counter_value: {
      type: DataTypes.BIGINT,
      defaultValue: 0,
      allowNull: false,
    },
    // created_at and updated_at are managed by Sequelize via timestamps: true
    // However, for a simple key-value store, timestamps might not be strictly necessary.
    // If only creation time is needed, or manual updates, adjust accordingly.
    // The task.txt implies this is a simple key-value, so timestamps: false might be better.
    // Let's go with timestamps: false as per the suggestion.
  }, {
    timestamps: false, // No createdAt or updatedAt fields
    underscored: true,
    tableName: 'stats_counters',
  });

  // No associations typically for a simple counter table

  return StatsCounter;
};

require('dotenv').config();

const app = require('./app');
const connectDB = require('./config/database');
const seedDatabase = require('./seed/seed');

const PORT = process.env.PORT || 3000;

// Start server
const startServer = async () => {
  try {
    // Connect to MongoDB
    await connectDB();
    console.log('MongoDB connected successfully');
    
    // Seed database
    await seedDatabase();
    console.log('Database seeded successfully');
    
    // Start listening
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
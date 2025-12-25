const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authenticate = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Support both 'userId' and 'sub' (JWT standard) fields
    const userId = decoded.userId || decoded.sub;

    if (!userId) {
      console.error('Token missing userId/sub field:', decoded);
      return res.status(401).json({ message: 'Invalid token format' });
    }

    console.log('Looking up user with ID:', userId);

    // Get user with roles and permissions
    const user = await User.findById(userId)
      .populate({
        path: 'roles',
        populate: {
          path: 'permissions'
        }
      })
      .select('-password');

    console.log('User lookup result:', user ? `Found: ${user.email}` : 'Not found');

    if (!user || !user.isActive) {
      return res.status(401).json({ message: 'Invalid token or user not found' });
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    return res.status(500).json({ message: 'Authentication error' });
  }
};

module.exports = authenticate;
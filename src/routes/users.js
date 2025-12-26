const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Role = require('../models/Role');
const authenticate = require('../middleware/auth');
const { hasPermission } = require('../middleware/rbac');

const router = express.Router();

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 */
router.get('/', authenticate, hasPermission('users:read'), async (req, res) => {
  try {
    const users = await User.find()
        .populate({
          path: 'roles',
          populate: {
            path: 'permissions',
            select: 'name'
          }
        })
        .select('-password');
    
    res.json({ users, count: users.length });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Error fetching users' });
  }
});

/**
 * @swagger
 * /users:
 *   post:
 *     summary: Create a new user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - name
 *               - roles
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               roles:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       201:
 *         description: User created
 *       400:
 *         description: Invalid input
 *       403:
 *         description: Forbidden
 */
router.post('/', 
  authenticate, 
  hasPermission('users:write'),
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('name').notEmpty().trim(),
    body('roles').isArray().notEmpty()
  ],
  async (req, res) => {
    try {
      // Validate input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password, name, roles: roleNames } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
      }

      // Find roles
      const roles = await Role.find({ name: { $in: roleNames } });
      if (roles.length !== roleNames.length) {
        return res.status(400).json({ message: 'Invalid roles specified' });
      }

      // Create user
      const user = new User({
        email,
        password,
        name,
        roles: roles.map(r => r._id)
      });

      await user.save();

      // Populate roles for response
      await user.populate('roles');

      res.status(201).json({ 
        message: 'User created successfully',
        user: user.toJSON()
      });
    } catch (error) {
      console.error('Create user error:', error);
      res.status(500).json({ message: 'Error creating user' });
    }
  }
);

module.exports = router;
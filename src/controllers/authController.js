const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is not defined');
}

exports.login = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    console.log('Login attempt for:', email);

    const user = await User.findOne({ email, isActive: true })
      .populate({
        path: 'roles',
        populate: { path: 'permissions' }
      });

    console.log('User found:', user ? 'Yes' : 'No');

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    console.log('Password verified successfully');

    const roles = user.roles.map(r => r.name);
    const permissions = user.roles.flatMap(r =>
      r.permissions.map(p => p.name)
    );

    const token = jwt.sign(
      {
        sub: user._id.toString(),
        userId: user._id.toString(), // Also include userId for backward compatibility
        roles,
        permissions
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    console.log('Token generated, sub:', user._id.toString());

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        roles
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    next(err);
  }
};
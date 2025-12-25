const express = require('express');
const { body } = require('express-validator');
const { login } = require('../controllers/authController');
const { loginRateLimiter } = require('../middleware/ratelimit');

const router = express.Router();

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful
 *       400:
 *         description: Invalid credentials
 */
router.post(
  '/login',
  loginRateLimiter,
  [
    body('email').trim().isEmail().normalizeEmail(),
    body('password').trim().notEmpty()
  ],
  login
);

module.exports = router;
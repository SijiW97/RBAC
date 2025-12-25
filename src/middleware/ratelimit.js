const rateLimit = require('express-rate-limit');

exports.loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 5,                  // 5 attempts per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: 'Too many login attempts. Try again later.'
  }
});

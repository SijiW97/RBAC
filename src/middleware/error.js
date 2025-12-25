//General error handling middleware
const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;

  res.status(status).json({
    message: err.message,
    ...(process.env.NODE_ENV === "development" && { stack: err.stack })
  });
};

module.exports = {
  errorHandler
};

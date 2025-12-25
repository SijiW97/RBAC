// Check if user has specific permission
const hasPermission = (requiredPermission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    // Get all permissions from user's roles
    const userPermissions = [];
    req.user.roles.forEach(role => {
      role.permissions.forEach(permission => {
        if (!userPermissions.includes(permission.name)) {
          userPermissions.push(permission.name);
        }
      });
    });

    // Check if user has required permission
    if (userPermissions.includes(requiredPermission)) {
      return next();
    }

    return res.status(403).json({ 
      message: 'Forbidden: Insufficient permissions',
      required: requiredPermission
    });
  };
};

// Check if user has any of the specified roles
const hasRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    // Get user's role names
    const userRoles = req.user.roles.map(role => role.name);

    // Check if user has any of the allowed roles
    const hasRequiredRole = allowedRoles.some(role => userRoles.includes(role));

    if (hasRequiredRole) {
      return next();
    }

    return res.status(403).json({ 
      message: 'Forbidden: Insufficient role',
      required: allowedRoles,
      current: userRoles
    });
  };
};

// Check if user has multiple permissions (all required)
const hasAllPermissions = (...requiredPermissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Authentication required' });
    }

    // Get all permissions from user's roles
    const userPermissions = [];
    req.user.roles.forEach(role => {
      role.permissions.forEach(permission => {
        if (!userPermissions.includes(permission.name)) {
          userPermissions.push(permission.name);
        }
      });
    });

    // Check if user has all required permissions
    const hasAll = requiredPermissions.every(perm => userPermissions.includes(perm));

    if (hasAll) {
      return next();
    }

    return res.status(403).json({ 
      message: 'Forbidden: Insufficient permissions',
      required: requiredPermissions,
      current: userPermissions
    });
  };
};

module.exports = {
  hasPermission,
  hasRole,
  hasAllPermissions
};
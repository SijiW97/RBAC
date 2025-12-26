const User = require('../models/User');
const Role = require('../models/Role');
const Permission = require('../models/Permission');

const seedDatabase = async () => {
  try {
    // Check if already seeded
    const existingPermissions = await Permission.countDocuments();
    if (existingPermissions > 0) {
      console.log('Database already seeded, skipping...');
      return;
    }

    console.log('Seeding database...');

    // Created Permissions
    const permissions = await Permission.insertMany([
      { name: 'users:read', description: 'Read user information' },
      { name: 'users:write', description: 'Create and update users' },
      { name: 'projects:read', description: 'Read project information' },
      { name: 'projects:write', description: 'Create and update projects' },
      { name: 'projects:delete', description: 'Delete projects' }
    ]);

    console.log('Permissions created');

    // Mapped permissions by name
    const permMap = {};
    permissions.forEach(p => {
      permMap[p.name] = p._id;
    });

    // Created Roles with permissions
    const adminRole = await Role.create({
      name: 'admin',
      description: 'Full system access',
      permissions: [
        permMap['users:read'],
        permMap['users:write'],
        permMap['projects:read'],
        permMap['projects:write'],
        permMap['projects:delete']
      ]
    });

    const managerRole = await Role.create({
      name: 'manager',
      description: 'Project read/write, user read',
      permissions: [
        permMap['users:read'],
        permMap['projects:read'],
        permMap['projects:write']
      ]
    });

    const viewerRole = await Role.create({
      name: 'viewer',
      description: 'Read-only project access',
      permissions: [
        permMap['projects:read']
      ]
    });

    console.log('Roles created');

    // Created Users
    await User.create([
      {
        email: 'admin@example.com',
        password: 'admin123',
        name: 'Admin User',
        roles: [adminRole._id]
      },
      {
        email: 'manager@example.com',
        password: 'manager123',
        name: 'Manager User',
        roles: [managerRole._id]
      },
      {
        email: 'viewer@example.com',
        password: 'viewer123',
        name: 'Viewer User',
        roles: [viewerRole._id]
      }
    ]);
  } catch (error) {
    console.error('Error seeding database:', error);
    throw error;
  }
};

module.exports = seedDatabase;
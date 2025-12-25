const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

// Set environment variables for testing
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.NODE_ENV = 'test';

// Import models after mongoose is connected
let User, Role, Permission, Project;

const app = require('../src/app');

let mongoServer;
let adminToken, managerToken, viewerToken;
let testProjectId;

beforeAll(async () => {
  // Start in-memory MongoDB server
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // Connect to the in-memory database
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  // Import models after connection
  User = require('../src/models/User');
  Role = require('../src/models/Role');
  Permission = require('../src/models/Permission');
  Project = require('../src/models/Project');

  // Seed the database
  await seedTestDatabase();

  // Set JWT secret for tests
  process.env.JWT_SECRET = 'test-secret';
  
  // Generate tokens
  const admin = await User.findOne({ email: 'admin@example.com' });
  const manager = await User.findOne({ email: 'manager@example.com' });
  const viewer = await User.findOne({ email: 'viewer@example.com' });

  adminToken = generateToken(admin);
  managerToken = generateToken(manager);
  viewerToken = generateToken(viewer);

  // Create a test project
  const testProject = new Project({
    name: 'Test Project',
    description: 'Test Description',
    status: 'active',
    createdBy: admin._id
  });
  await testProject.save();
  testProjectId = testProject._id;
});

afterAll(async () => {
  // Close database connection and stop server
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
  await mongoServer.stop();
});

const generateToken = (user) => {
  const jwt = require('jsonwebtoken');
  return jwt.sign(
    { 
      userId: user._id,
      email: user.email,
      roles: user.roles.map(r => r.name)
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
};

const seedTestDatabase = async () => {
  // Create Permissions
  const permissions = await Permission.insertMany([
    { name: 'users:read', description: 'Read user information' },
    { name: 'users:write', description: 'Create and update users' },
    { name: 'projects:read', description: 'Read project information' },
    { name: 'projects:write', description: 'Create and update projects' },
    { name: 'projects:delete', description: 'Delete projects' }
  ]);

  // Map permissions
  const permMap = {};
  permissions.forEach(p => {
    permMap[p.name] = p._id;
  });

  // Create Roles
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

  // Create Users
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
};

describe('Authentication Tests', () => {
  test('Should login successfully with valid credentials', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({
        email: 'admin@example.com',
        password: 'admin123'
      });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
    expect(res.body.user).toHaveProperty('email', 'admin@example.com');
  });

  test('Should fail login with invalid credentials', async () => {
    
    const res = await request(app)
      .post('/auth/login')
      .send({
        email: 'admin@example.com',
        password: 'wrongpassword'
      });

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('message');
    
  });

  test('Should return 401 for missing token', async () => {
    const res = await request(app).get('/users');

    expect(res.status).toBe(401);
    expect(res.body.message).toContain('No token provided');
  });

  test('Should return 401 for invalid token', async () => {
    const res = await request(app)
      .get('/users')
      .set('Authorization', 'Bearer invalid-token');

    expect(res.status).toBe(401);
    expect(res.body.message).toContain('Invalid token');
  });
});

describe('RBAC - Viewer Role Tests', () => {
  test('Viewer can read projects', async () => {
    const res = await request(app)
      .get('/projects')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('projects');
  });

  test('Viewer cannot create projects (403 Forbidden)', async () => {
    const res = await request(app)
      .post('/projects')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({
        name: 'Unauthorized Project',
        description: 'This should fail'
      });

    expect(res.status).toBe(403);
    expect(res.body.message).toContain('Forbidden');
  });

  test('Viewer cannot delete projects (403 Forbidden)', async () => {
    const res = await request(app)
      .delete(`/projects/${testProjectId}`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(403);
    expect(res.body.message).toContain('Forbidden');
  });

  test('Viewer cannot read users (403 Forbidden)', async () => {
    const res = await request(app)
      .get('/users')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(403);
    expect(res.body.message).toContain('Forbidden');
  });

  test('Viewer cannot create users (403 Forbidden)', async () => {
    const res = await request(app)
      .post('/users')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({
        email: 'newuser@example.com',
        password: 'password123',
        name: 'New User',
        roles: ['viewer']
      });

    expect(res.status).toBe(403);
    expect(res.body.message).toContain('Forbidden');
  });
});

describe('RBAC - Manager Role Tests', () => {
  test('Manager can read projects', async () => {
    const res = await request(app)
      .get('/projects')
      .set('Authorization', `Bearer ${managerToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('projects');
  });

  test('Manager can create projects', async () => {
    const res = await request(app)
      .post('/projects')
      .set('Authorization', `Bearer ${managerToken}`)
      .send({
        name: 'Manager Project',
        description: 'Created by manager'
      });

    expect(res.status).toBe(201);
    expect(res.body.project).toHaveProperty('name');
  });

  test('Manager can update projects', async () => {
    const res = await request(app)
      .put(`/projects/${testProjectId}`)
      .set('Authorization', `Bearer ${managerToken}`)
      .send({
        status: 'on-hold'
      });

    expect(res.status).toBe(200);
  });

  test('Manager cannot delete projects (403 Forbidden)', async () => {
    const res = await request(app)
      .delete(`/projects/${testProjectId}`)
      .set('Authorization', `Bearer ${managerToken}`);

    expect(res.status).toBe(403);
    expect(res.body.message).toContain('Forbidden');
  });

  test('Manager can read users', async () => {
    const res = await request(app)
      .get('/users')
      .set('Authorization', `Bearer ${managerToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('users');
  });

  test('Manager cannot create users (403 Forbidden)', async () => {
    const res = await request(app)
      .post('/users')
      .set('Authorization', `Bearer ${managerToken}`)
      .send({
        email: 'newuser@example.com',
        password: 'password123',
        name: 'New User',
        roles: ['viewer']
      });

    expect(res.status).toBe(403);
    expect(res.body.message).toContain('Forbidden');
  });
});

describe('RBAC - Admin Role Tests', () => {
  test('Admin can read projects', async () => {
    const res = await request(app)
      .get('/projects')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('projects');
  });

  test('Admin can create projects', async () => {
    const res = await request(app)
      .post('/projects')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'Admin Project',
        description: 'Created by admin'
      });

    expect(res.status).toBe(201);
    expect(res.body.project).toHaveProperty('name');
  });

  test('Admin can update projects', async () => {
    const res = await request(app)
      .put(`/projects/${testProjectId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'Updated Test Project'
      });

    expect(res.status).toBe(200);
  });

  test('Admin can delete projects', async () => {
    const res = await request(app)
      .delete(`/projects/${testProjectId}`)
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
  });

  test('Admin can read users', async () => {
    const res = await request(app)
      .get('/users')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('users');
  });

  test('Admin can create users', async () => {
    const res = await request(app)
      .post('/users')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        email: 'testuser@example.com',
        password: 'password123',
        name: 'Test User',
        roles: ['viewer']
      });

    expect(res.status).toBe(201);
    expect(res.body.message).toContain('created successfully');
  });
});

describe('HTTP Status Code Tests', () => {
  test('Should return 401 for missing authentication', async () => {
    const res = await request(app).get('/projects');
    expect(res.status).toBe(401);
  });

  test('Should return 403 for insufficient permissions', async () => {
    const res = await request(app)
      .delete(`/projects/${testProjectId}`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(403);
  });

  test('Should return 400 for invalid input', async () => {
    const res = await request(app)
      .post('/projects')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: '' // Empty name should fail validation
      });

    expect(res.status).toBe(400);
  });

  test('Health check should return 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
    test('it should 404 for route not found', async () => {
    const res = await request(app).get('/hello');
    expect(res.status).toBe(404);
  });

    test('Should return 401 for user not found', async () => {
    const res = await request(app).get('/projects');
    expect(res.status).toBe(401);
  });
});
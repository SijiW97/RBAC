const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.NODE_ENV = 'test';

let User, Role, Permission, Project;

const app = require('../src/app');
const { hasAllPermissions, hasRole, hasPermission } = require('../src/middleware/rbac');
const { errorHandler } = require('../src/middleware/error');

let mongoServer;
let adminToken, managerToken, viewerToken;
let testProjectId;

beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });
    User = require('../src/models/User');
    Role = require('../src/models/Role');
    Permission = require('../src/models/Permission');
    Project = require('../src/models/Project');

    await seedTestDatabase();

    process.env.JWT_SECRET = 'test-secret';

    // Generate tokens
    const admin = await User.findOne({ email: 'admin@example.com' });
    const manager = await User.findOne({ email: 'manager@example.com' });
    const viewer = await User.findOne({ email: 'viewer@example.com' });

    adminToken = generateToken(admin);
    managerToken = generateToken(manager);
    viewerToken = generateToken(viewer);

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
    const permissions = await Permission.insertMany([
        { name: 'users:read', description: 'Read user information' },
        { name: 'users:write', description: 'Create and update users' },
        { name: 'projects:read', description: 'Read project information' },
        { name: 'projects:write', description: 'Create and update projects' },
        { name: 'projects:delete', description: 'Delete projects' }
    ]);

    const permMap = {};
    permissions.forEach(p => {
        permMap[p.name] = p._id;
    });

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
});

describe('Projects API Tests', () => {
    test('GET /projects - should return paginated projects list', async () => {
        const res = await request(app)
            .get('/projects')
            .set('Authorization', `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('projects');
        expect(res.body).toHaveProperty('count');
        expect(res.body).toHaveProperty('total');
        expect(res.body).toHaveProperty('page');
        expect(res.body).toHaveProperty('totalPages');
        expect(Array.isArray(res.body.projects)).toBe(true);
    });

    test('GET /projects - should support pagination', async () => {
        const res = await request(app)
            .get('/projects?page=1&limit=5')
            .set('Authorization', `Bearer ${adminToken}`);

        expect(res.status).toBe(200);
        expect(res.body.page).toBe(1);
        expect(res.body.projects.length).toBeLessThanOrEqual(5);
    });

    test('GET /projects/:id - should return 404 for non-existent project', async () => {
        const fakeId = '507f1f77bcf86cd799439011';
        const res = await request(app)
            .get(`/projects/${fakeId}`)
            .set('Authorization', `Bearer ${adminToken}`);

        expect(res.status).toBe(404);
        expect(res.body.message).toBe('Project not found');
    });

    test('GET /projects/:id - should return 404 for invalid ID', async () => {
        const res = await request(app)
            .get('/projects/invalid-id')
            .set('Authorization', `Bearer ${adminToken}`);

        expect(res.status).toBe(404);
        expect(res.body.message).toBe('Project not found');
    });

    test('POST /projects - should create new project', async () => {
        const projectData = {
            name: 'New Test Project',
            description: 'A project created in tests',
            status: 'active'
        };

        const res = await request(app)
            .post('/projects')
            .set('Authorization', `Bearer ${adminToken}`)
            .send(projectData);

        expect(res.status).toBe(201);
        expect(res.body).toHaveProperty('project');
        expect(res.body.project.name).toBe(projectData.name);
        expect(res.body.project.description).toBe(projectData.description);
        expect(res.body.project.status).toBe(projectData.status);
        expect(res.body.project).toHaveProperty('createdBy');
    });

    test('POST /projects - should return 400 for validation errors', async () => {
        const res = await request(app)
            .post('/projects')
            .set('Authorization', `Bearer ${adminToken}`)
            .send({
                name: '', // Empty name
                description: 'Valid description'
            });

        expect(res.status).toBe(400);
        expect(res.body).toHaveProperty('errors');
    });

    test('POST /projects - should default status to active', async () => {
        const res = await request(app)
            .post('/projects')
            .set('Authorization', `Bearer ${adminToken}`)
            .send({
                name: 'Project without status',
                description: 'Description'
            });

        expect(res.status).toBe(201);
        expect(res.body.project.status).toBe('active');
    });

    test('PUT /projects/:id - should return 404 for non-existent project', async () => {
        const fakeId = '507f1f77bcf86cd799439011';
        const res = await request(app)
            .put(`/projects/${fakeId}`)
            .set('Authorization', `Bearer ${adminToken}`)
            .send({ name: 'Updated Name' });

        expect(res.status).toBe(404);
        expect(res.body.message).toBe('Project not found');
    });

    test('DELETE /projects/:id - should delete project', async () => {
        // First create a project to delete
        const createRes = await request(app)
            .post('/projects')
            .set('Authorization', `Bearer ${adminToken}`)
            .send({
                name: 'Project to Delete',
                description: 'Will be deleted'
            });

        const projectId = createRes.body.project._id;

        const deleteRes = await request(app)
            .delete(`/projects/${projectId}`)
            .set('Authorization', `Bearer ${adminToken}`);

        expect(deleteRes.status).toBe(200);
        expect(deleteRes.body.message).toBe('Project deleted successfully');

        // Verify it's deleted
        const getRes = await request(app)
            .get(`/projects/${projectId}`)
            .set('Authorization', `Bearer ${adminToken}`);

        expect(getRes.status).toBe(404);
    });

    test('DELETE /projects/:id - should return 404 for non-existent project', async () => {
        const fakeId = '507f1f77bcf86cd799439011';
        const res = await request(app)
            .delete(`/projects/${fakeId}`)
            .set('Authorization', `Bearer ${adminToken}`);

        expect(res.status).toBe(404);
        expect(res.body.message).toBe('Project not found');
    });
});

test('Should return 401 for user not found', async () => {
    const res = await request(app).get('/projects');
    expect(res.status).toBe(401);
});


describe('hasPermission', () => {
    const mockRes = () => {
        const res = {};
        res.status = jest.fn().mockReturnValue(res);
        res.json = jest.fn();
        return res;
    };
    test('returns 401 if user is not authenticated', () => {
        const req = {};
        const res = mockRes();
        const next = jest.fn();

        hasPermission('READ_USER')(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Authentication required' });
        expect(next).not.toHaveBeenCalled();
    });

    test('calls next if user has required permission', () => {
        const req = {
            user: {
                roles: [
                    {
                        permissions: [{ name: 'READ_USER' }]
                    }
                ]
            }
        };
        const res = mockRes();
        const next = jest.fn();

        hasPermission('READ_USER')(req, res, next);

        expect(next).toHaveBeenCalled();
    });

    test('returns 403 if user lacks required permission', () => {
        const req = {
            user: {
                roles: [
                    {
                        permissions: [{ name: 'WRITE_USER' }]
                    }
                ]
            }
        };
        const res = mockRes();
        const next = jest.fn();

        hasPermission('READ_USER')(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
            message: 'Forbidden: Insufficient permissions',
            required: 'READ_USER'
        });
        expect(next).not.toHaveBeenCalled();
    });
});

describe('hasRole', () => {
    const mockRes = () => {
        const res = {};
        res.status = jest.fn().mockReturnValue(res);
        res.json = jest.fn();
        return res;
    };
    test('returns 401 if user is not authenticated', () => {
        const req = {};
        const res = mockRes();
        const next = jest.fn();

        hasRole('ADMIN')(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Authentication required' });
    });

    test('calls next if user has required role', () => {
        const req = {
            user: {
                roles: [{ name: 'ADMIN' }]
            }
        };
        const res = mockRes();
        const next = jest.fn();

        hasRole('ADMIN', 'SUPER_ADMIN')(req, res, next);

        expect(next).toHaveBeenCalled();
    });

    test('returns 403 if user lacks role', () => {
        const req = {
            user: {
                roles: [{ name: 'USER' }]
            }
        };
        const res = mockRes();
        const next = jest.fn();

        hasRole('ADMIN')(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
            message: 'Forbidden: Insufficient role',
            required: ['ADMIN'],
            current: ['USER']
        });
    });
});

describe('hasAllPermissions', () => {
    const mockRes = () => {
        const res = {};
        res.status = jest.fn().mockReturnValue(res);
        res.json = jest.fn();
        return res;
    };
    test('returns 401 if user is not authenticated', () => {
        const req = {};
        const res = mockRes();
        const next = jest.fn();

        hasAllPermissions('READ', 'WRITE')(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ message: 'Authentication required' });
    });

    test('calls next if user has all permissions', () => {
        const req = {
            user: {
                roles: [
                    {
                        permissions: [{ name: 'READ' }, { name: 'WRITE' }]
                    }
                ]
            }
        };
        const res = mockRes();
        const next = jest.fn();

        hasAllPermissions('READ', 'WRITE')(req, res, next);

        expect(next).toHaveBeenCalled();
    });

    test('returns 403 if user lacks one or more permissions', () => {
        const req = {
            user: {
                roles: [
                    {
                        permissions: [{ name: 'READ' }]
                    }
                ]
            }
        };
        const res = mockRes();
        const next = jest.fn();

        hasAllPermissions('READ', 'WRITE')(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
            message: 'Forbidden: Insufficient permissions',
            required: ['READ', 'WRITE'],
            current: ['READ']
        });
    });
});


describe('errorHandler middleware', () => {

    const mockRes = () => {
        const res = {};
        res.status = jest.fn().mockReturnValue(res);
        res.json = jest.fn();
        return res;
    };

    afterEach(() => {
        delete process.env.NODE_ENV;
    });

    test('returns provided error status and message', () => {
        process.env.NODE_ENV = 'production';

        const err = {
            status: 400,
            message: 'Bad Request'
        };

        const req = {};
        const res = mockRes();
        const next = jest.fn();

        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
            message: 'Bad Request'
        });
    });

    test('returns 500 and includes stack trace in development', () => {
        process.env.NODE_ENV = 'development';

        const err = new Error('Something broke');

        const req = {};
        const res = mockRes();
        const next = jest.fn();

        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);

        const response = res.json.mock.calls[0][0];
        expect(response.message).toBe('Something broke');
        expect(response.stack).toBeDefined(); // dev-only behavior
    });
});

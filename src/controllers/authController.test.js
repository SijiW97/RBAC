const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { validationResult } = require('express-validator');
process.env.JWT_SECRET = 'test-secret-key';
process.env.JWT_EXPIRES_IN = '24h';
const { login } = require('./authController');

jest.mock(('../models/User'));
jest.mock('express-validator');
jest.mock('jsonwebtoken');

describe('AuthController - login', () => {
    let req, res, next;

    beforeEach(() => {
        req = {
            body: {
                email: 'test@example.com',
                password: 'password123'
            }
        };

        // Setup response object
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        };

        // Setup next function
        next = jest.fn();

        // Reset all mocks
        jest.clearAllMocks();

        // Set JWT_SECRET for tests
        process.env.JWT_SECRET = 'test-secret-key';
        process.env.JWT_EXPIRES_IN = '24h';
    });

    afterEach(() => {
        jest.resetAllMocks();
    });

    describe('Validation', () => {
        test('should return 400 if validation errors exist', async () => {
            // Mock validation errors
            validationResult.mockReturnValue({
                isEmpty: () => false,
                array: () => [
                    { field: 'email', msg: 'Invalid email' }
                ]
            });

            await login(req, res, next);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({
                errors: [{ field: 'email', msg: 'Invalid email' }]
            });
        });

        test('should continue if no validation errors', async () => {
            validationResult.mockReturnValue({
                isEmpty: () => true
            });

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(null)
            });

            await login(req, res, next);

            expect(validationResult).toHaveBeenCalled();
        });
    });

    describe('User Authentication', () => {
        test('should return 401 if user not found', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(null)
            });

            await login(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({
                message: 'Invalid credentials'
            });
        });

        test('should return 401 if user is inactive', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(null)
            });

            await login(req, res, next);

            expect(User.findOne).toHaveBeenCalledWith({
                email: 'test@example.com',
                isActive: true
            });
            expect(res.status).toHaveBeenCalledWith(401);
        });

        test('should return 401 if password is incorrect', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: '507f1f77bcf86cd799439011',
                email: 'test@example.com',
                name: 'Test User',
                comparePassword: jest.fn().mockResolvedValue(false),
                roles: [
                    {
                        name: 'admin',
                        permissions: [{ name: 'users:read' }]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            await login(req, res, next);

            expect(mockUser.comparePassword).toHaveBeenCalledWith('password123');
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({
                message: 'Invalid credentials'
            });
        });
    });

    describe('Successful Login', () => {
        test('should return token and user data on successful login', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'test@example.com',
                name: 'Test User',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'admin',
                        permissions: [
                            { name: 'users:read' },
                            { name: 'users:write' }
                        ]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-jwt-token');

            await login(req, res, next);

            expect(mockUser.comparePassword).toHaveBeenCalledWith('password123');
            expect(jwt.sign).toHaveBeenCalledWith(
                {
                    userId: '507f1f77bcf86cd799439011',
                    roles: ['admin'],
                    permissions: ['users:read', 'users:write']
                },
                'test-secret-key',
                { expiresIn: '24h' }
            );
            expect(res.json).toHaveBeenCalledWith({
                token: 'mock-jwt-token',
                user: {
                    id: mockUser._id,
                    email: 'test@example.com',
                    name: 'Test User',
                    roles: ['admin']
                }
            });
        });

        test('should include userId in token', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'test@example.com',
                name: 'Test User',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'viewer',
                        permissions: [{ name: 'projects:read' }]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-token');

            await login(req, res, next);

            const tokenPayload = jwt.sign.mock.calls[0][0];
            expect(tokenPayload).toHaveProperty('userId', '507f1f77bcf86cd799439011');
        });

        test('should flatten permissions from multiple roles', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'test@example.com',
                name: 'Test User',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'admin',
                        permissions: [
                            { name: 'users:read' },
                            { name: 'users:write' }
                        ]
                    },
                    {
                        name: 'manager',
                        permissions: [
                            { name: 'projects:read' },
                            { name: 'projects:write' }
                        ]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-token');

            await login(req, res, next);

            const tokenPayload = jwt.sign.mock.calls[0][0];
            expect(tokenPayload.permissions).toEqual([
                'users:read',
                'users:write',
                'projects:read',
                'projects:write'
            ]);
            expect(tokenPayload.roles).toEqual(['admin', 'manager']);
        });

        test('should use default expiration if JWT_EXPIRES_IN not set', async () => {
            delete process.env.JWT_EXPIRES_IN;

            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'test@example.com',
                name: 'Test User',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'admin',
                        permissions: [{ name: 'users:read' }]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-token');

            await login(req, res, next);

            expect(jwt.sign).toHaveBeenCalledWith(
                expect.any(Object),
                expect.any(String),
                { expiresIn: '24h' }
            );
        });
    });

    describe('Token Content', () => {
        test('should include all required fields in token', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'admin@example.com',
                name: 'Admin User',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'admin',
                        permissions: [
                            { name: 'users:read' },
                            { name: 'users:write' },
                            { name: 'projects:read' }
                        ]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-token');

            await login(req, res, next);

            const tokenPayload = jwt.sign.mock.calls[0][0];
            expect(tokenPayload).toHaveProperty('userId');
            expect(tokenPayload).toHaveProperty('roles');
            expect(tokenPayload).toHaveProperty('permissions');
            expect(Array.isArray(tokenPayload.roles)).toBe(true);
            expect(Array.isArray(tokenPayload.permissions)).toBe(true);
        });

        test('should convert ObjectId to string in token', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'test@example.com',
                name: 'Test User',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'viewer',
                        permissions: [{ name: 'projects:read' }]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-token');

            await login(req, res, next);

            const tokenPayload = jwt.sign.mock.calls[0][0];
            expect(typeof tokenPayload.userId).toBe('string');
            expect(tokenPayload.userId).toBe('507f1f77bcf86cd799439011');
        });

        test('should call next(err) when jwt.sign throws error', async () => {
            process.env.JWT_SECRET = 'test_secret';

            const jwtError = new Error('JWT failure');

            validationResult.mockReturnValue({
                isEmpty: () => true
            });

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue({
                    _id: '123',
                    email: 'test@test.com',
                    name: 'Test',
                    roles: [
                        {
                            name: 'USER',
                            permissions: [
                                { name: 'READ' }
                            ]
                        }
                    ],
                    comparePassword: jest.fn().mockResolvedValue(true),

                })
            });

            jwt.sign.mockImplementation(() => {
                throw jwtError;
            });

            const req = {
                body: { email: 'test@test.com', password: 'password' }
            };

            const res = {
                json: jest.fn()
            };

            const next = jest.fn();

            await login(req, res, next);

            expect(next).toHaveBeenCalledTimes(1);
            expect(next).toHaveBeenCalledWith(jwtError);
        });


    });

    describe('Response Format', () => {
        test('should return correct response structure', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'test@example.com',
                name: 'Test User',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'viewer',
                        permissions: [{ name: 'projects:read' }]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-jwt-token');

            await login(req, res, next);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    token: expect.any(String),
                    user: expect.objectContaining({
                        id: expect.any(Object),
                        email: expect.any(String),
                        name: expect.any(String),
                        roles: expect.any(Array)
                    })
                })
            );
        });

        test('should not include password in response', async () => {
            validationResult.mockReturnValue({ isEmpty: () => true });

            const mockUser = {
                _id: { toString: () => '507f1f77bcf86cd799439011' },
                email: 'test@example.com',
                name: 'Test User',
                password: 'hashed-password',
                comparePassword: jest.fn().mockResolvedValue(true),
                roles: [
                    {
                        name: 'admin',
                        permissions: [{ name: 'users:read' }]
                    }
                ]
            };

            User.findOne.mockReturnValue({
                populate: jest.fn().mockResolvedValue(mockUser)
            });

            jwt.sign.mockReturnValue('mock-token');

            await login(req, res, next);

            const response = res.json.mock.calls[0][0];
            expect(response.user).not.toHaveProperty('password');
        });
    });


});
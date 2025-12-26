const Project = require('../models/Project');
const { getAllProjects, createProject } = require('./projectController');

const { validationResult } = require('express-validator');
jest.mock('express-validator', () => ({
  validationResult: jest.fn()
}));

jest.mock('../models/Project', () => {
  return {
    find: jest.fn(),
    countDocuments: jest.fn(),
    prototype: {
      save: jest.fn()
    }
  };
});
const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn();
  return res;
};

const mockNext = jest.fn();

describe('getAllProjects', () => {
  it('should return paginated projects', async () => {
    const req = {
      query: { page: '1', limit: '10' }
    };
    const res = mockRes();

    const mockProjects = [
      { name: 'Project 1' },
      { name: 'Project 2' }
    ];
    Project.find.mockReturnValue({
      populate: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      skip: jest.fn().mockReturnThis(),
      limit: jest.fn().mockResolvedValue(mockProjects)
    });

    Project.countDocuments.mockResolvedValue(20);

    await getAllProjects(req, res, mockNext);

    expect(Project.find).toHaveBeenCalled();
    expect(Project.countDocuments).toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith({
      projects: mockProjects,
      count: 2,
      total: 20,
      page: 1,
      totalPages: 2
    });
  });
});

it('should call next on error', async () => {
  const req = { query: {} };
  const res = mockRes();

  Project.find.mockImplementation(() => {
    throw new Error('DB error');
  });

  await getAllProjects(req, res, mockNext);

  expect(mockNext).toHaveBeenCalled();
});
it('should return 400 if validation fails', async () => {
  validationResult.mockReturnValue({
    isEmpty: () => false,
    array: () => [{ msg: 'Name is required' }]
  });

  const req = { body: {} };
  const res = mockRes();

  await createProject(req, res, mockNext);

  expect(res.status).toHaveBeenCalledWith(400);
  expect(res.json).toHaveBeenCalledWith({
    errors: [{ msg: 'Name is required' }]
  });
});
it('should call next on error', async () => {
  const req = { query: {} };
  const res = mockRes();
  Project.find.mockImplementation(() => {
    throw new Error('DB error');
  });
  await createProject(req, res, mockNext);
  expect(mockNext).toHaveBeenCalled();
});

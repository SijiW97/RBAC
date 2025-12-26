const { validationResult } = require('express-validator');
const Project = require('../models/Project');

/**
 * Get all projects with pagination
 */
exports.getAllProjects = async (req, res, next) => {
  try {
    const page = Number(req.query.page) || 1;
    const limit = Math.min(Number(req.query.limit) || 10, 50);
    const skip = (page - 1) * limit;

    const projects = await Project.find()
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const total = await Project.countDocuments();
    
    res.json({ 
      projects, 
      count: projects.length,
      total,
      page,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Get all projects error:', error);
    next(error);
  }
};


/**
 * Create new project
 */
exports.createProject = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, status } = req.body;

    const project = new Project({
      name,
      description,
      status: status || 'active',
      createdBy: req.user._id
    });

    await project.save();
    await project.populate('createdBy', 'name email');
    res.status(201).json({
      message: 'Project created successfully',
      project
    });
  } catch (error) {
    next(error);
  }
};
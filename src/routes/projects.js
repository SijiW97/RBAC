const express = require('express');
const { body, validationResult } = require('express-validator');
const Project = require('../models/Project');
const authenticate = require('../middleware/auth');
const { hasPermission } = require('../middleware/rbac');
const { readLimiter, apiLimiter } = require('../middleware/ratelimit');
const projectController = require('../controllers/projectController');

const router = express.Router();

/**
 * @swagger
 * /projects:
 *   get:
 *     summary: Get all projects
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *           maximum: 50
 *     responses:
 *       200:
 *         description: List of projects
 *       401:
 *         description: Unauthorized
 */
router.get(
  '/',
  readLimiter,
  authenticate,
  hasPermission('projects:read'),
  projectController.getAllProjects
);


/**
 * @swagger
 * /projects/{id}:
 *   get:
 *     summary: Get project by ID
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Project details
 *       404:
 *         description: Project not found
 */
router.get('/:id', apiLimiter, hasPermission('projects:read'), async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate('createdBy', 'name email');
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    res.json({ project });
  } catch (error) {
    console.error('Get project error:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Project not found' });
    }
    res.status(500).json({ message: 'Error fetching project' });
  }
});

/**
 * @swagger
 * /projects:
 *   post:
 *     summary: Create a new project
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - description
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               status:
 *                 type: string
 *                 enum: [active, completed, on-hold, cancelled]
 *     responses:
 *       201:
 *         description: Project created
 *       400:
 *         description: Invalid input
 */
router.post(
  '/',
  apiLimiter,
  authenticate,
  hasPermission('projects:write'),
  [
    body('name')
      .notEmpty().withMessage('Name is required')
      .trim()
      .isLength({ min: 3, max: 100 }).withMessage('Name must be between 3-100 characters'),
    body('description')
      .notEmpty().withMessage('Description is required')
      .trim()
      .isLength({ max: 1000 }).withMessage('Description cannot exceed 1000 characters'),
    body('status')
      .optional()
      .isIn(['active', 'completed', 'on-hold', 'cancelled'])
      .withMessage('Invalid status')
  ],
  projectController.createProject
);

/**
 * @swagger
 * /projects/{id}:
 *   put:
 *     summary: Update a project
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               status:
 *                 type: string
 *     responses:
 *       200:
 *         description: Project updated
 *       404:
 *         description: Project not found
 */
router.put('/:id',
  authenticate,
  hasPermission('projects:write'),
  [
    body('name').optional().notEmpty().trim(),
    body('description').optional().notEmpty().trim(),
    body('status').optional().isIn(['active', 'completed', 'on-hold', 'cancelled'])
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { name, description, status } = req.body;
      const updateData = {};
      
      if (name) updateData.name = name;
      if (description) updateData.description = description;
      if (status) updateData.status = status;

      const project = await Project.findByIdAndUpdate(
        req.params.id,
        updateData,
        { new: true, runValidators: true }
      ).populate('createdBy', 'name email');

      if (!project) {
        return res.status(404).json({ message: 'Project not found' });
      }

      res.json({
        message: 'Project updated successfully',
        project
      });
    } catch (error) {
      console.error('Update project error:', error);
      if (error.name === 'CastError') {
        return res.status(404).json({ message: 'Project not found' });
      }
      res.status(500).json({ message: 'Error updating project' });
    }
  }
);

/**
 * @swagger
 * /projects/{id}:
 *   delete:
 *     summary: Delete a project
 *     tags: [Projects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Project deleted
 *       404:
 *         description: Project not found
 */
router.delete('/:id', apiLimiter,authenticate, hasPermission('projects:delete'), async (req, res) => {
  try {
    const project = await Project.findByIdAndDelete(req.params.id);

    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }

    res.json({ 
      message: 'Project deleted successfully',
      project
    });
  } catch (error) {
    console.error('Delete project error:', error);
    if (error.name === 'CastError') {
      return res.status(404).json({ message: 'Project not found' });
    }
    res.status(500).json({ message: 'Error deleting project' });
  }
});

module.exports = router;
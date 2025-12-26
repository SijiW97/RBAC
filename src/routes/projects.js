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
router.put(
  '/:id',
  apiLimiter,
  authenticate,
  hasPermission('projects:write'),
  [
    body('name')
      .optional()
      .notEmpty().withMessage('Name cannot be empty')
      .trim()
      .isLength({ min: 3, max: 100 }),
    body('description')
      .optional()
      .notEmpty().withMessage('Description cannot be empty')
      .trim()
      .isLength({ max: 1000 }),
    body('status')
      .optional()
      .isIn(['active', 'completed', 'on-hold', 'cancelled'])
  ],
  projectController.updateProject
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
router.delete(
  '/:id',
  apiLimiter,
  authenticate,
  hasPermission('projects:delete'),
  projectController.deleteProject
);

module.exports = router;
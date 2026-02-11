const Joi = require('joi');
const { handleError } = require('../utils/errorHandler');
const { pool } = require('../database');

// Validation schema
const applicationIdSchema = Joi.string().required();

// Get application by ID
const getApplicationById = async (req, res) => {
  try {
    const { error, value } = applicationIdSchema.validate(req.params.id);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid application ID',
        details: error.details.map(d => d.message)
      });
    }

    const applicationId = value;
    
    const [rows] = await pool.execute(`
      SELECT 
        application_id, application_name, description, 
        created_at, updated_at, status
      FROM sa_applications 
      WHERE application_id = ?
    `, [applicationId]);
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
    
  } catch (error) {
    handleError(error, res, 'fetch application');
  }
};

// Get all applications (optional - for admin purposes)
const getAllApplications = async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        application_id, application_name, description, 
        created_at, updated_at, status
      FROM sa_applications 
      ORDER BY application_name ASC
    `);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
    
  } catch (error) {
    handleError(error, res, 'fetch applications');
  }
};

// Create new application
const createApplication = async (req, res) => {
  try {
    const schema = Joi.object({
      application_name: Joi.string().max(255).required(),
      description: Joi.string().optional(),
      status: Joi.string().valid('active', 'inactive').default('active')
    });

    const { error, value } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const { application_name, description, status } = value;
    
    const [result] = await pool.execute(`
      INSERT INTO sa_applications (application_name, description, status) 
      VALUES (?, ?, ?)
    `, [application_name, description || null, status]);
    
    // Fetch the created application
    const [newApp] = await pool.execute(`
      SELECT 
        application_id, application_name, description, 
        created_at, updated_at, status
      FROM sa_applications 
      WHERE application_id = ?
    `, [result.insertId]);
    
    res.status(201).json({
      success: true,
      message: 'Application created successfully',
      data: newApp[0]
    });
    
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Application name already exists'
      });
    }
    handleError(error, res, 'create application');
  }
};

// Get user applications
const getUserApplications = async (req, res) => {
  try {
    const userId = req.user.user_id;
    
    const [rows] = await pool.execute(`
      SELECT a.application_id, a.application_name, a.redirect_URL, a.description
      FROM sa_applications a
      INNER JOIN sa_app_user au ON a.application_id = au.application_id
      WHERE au.user_id = ?
      ORDER BY a.application_name
    `, [userId]);
    
    res.json({
      success: true,
      data: rows
    });
    
  } catch (error) {
    handleError(error, res, 'fetch user applications');
  }
};

module.exports = {
  getApplicationById,
  getAllApplications,
  createApplication,
  getUserApplications
};
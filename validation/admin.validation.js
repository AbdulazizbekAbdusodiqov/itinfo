const Joi = require("joi");

exports.adminValidation = (data) => {
  const adminSchema = Joi.object({
    name: Joi.string().trim().min(3).max(50).required().messages({
      "string.base": "Admin name must be a string",
      "string.empty": "Admin name is required",
      "string.min": "Admin name must be at least 3 characters",
      "string.max": "Admin name cannot exceed 50 characters",
    }),

    email: Joi.string().email().required(),
    phone: Joi.string().pattern(/^\d{2}-\d{3}-\d{2}-\d{2}$/),

    password: Joi.string().min(6).required().messages({
      "string.min": "Password must be at least 6 characters long",
      "any.required": "Password is required",
    }),

    is_active: Joi.boolean().default(true).messages({
      "boolean.base": "Admin active status must be true or false",
    }),

    is_creator: Joi.boolean().default(false).messages({
      "boolean.base": "Admin creator status must be true or false",
    }),
  });

  return adminSchema.validate(data, { abortEarly: false });
};
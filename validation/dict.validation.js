const Joi = require("joi");
exports.dictValidation = (data) => {
  const dictSchema = Joi.object({
    term: Joi.string().optional()
  });

  return dictSchema.validate(data, { abortEarly: false });
};

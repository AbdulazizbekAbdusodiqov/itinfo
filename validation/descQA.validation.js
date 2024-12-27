const Joi = require("joi");

exports.descQAValidation = (data) => {
  const descQASchema = Joi.object({
    qa_id: Joi.string().alphanum(),
    desc_id: Joi.string().alphanum(),
  });

  return descQASchema.validate(data, { abortEarly: false });
};

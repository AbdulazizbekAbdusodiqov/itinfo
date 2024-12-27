const Joi = require("joi");

exports.sinonymValidation = (data) => {
  const synSchema = Joi.object({
    desc_id: Joi.string().alphanum(),
    dict_id: Joi.string().alphanum(),
  });

  return synSchema.validate(data, { abortEarly: false });
};

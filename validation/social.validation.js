const Joi = require('joi');

exports.socialValidation = (data) => {
  const SocialSchema = Joi.object({
    social_name: Joi.string().required(),
  });

  return SocialSchema.validate(data, { abortEarly: false });
};
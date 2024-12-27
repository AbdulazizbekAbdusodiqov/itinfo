const Joi = require("joi");

exports.descValidation = (data) => {
  const descSchema = Joi.object({
    category_id: Joi.string().alphanum(),
    description: Joi.string()
      .min(3)
      .message("matn 3ta harfdan ko'p bo'lishsin")
      .max(10000)
      .message("10000tadan kam, 3tadan ko'p")
      .required(),
  });

  return descSchema.validate(data, { abortEarly: false });
};

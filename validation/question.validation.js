const Joi = require("joi");

exports.questionValidation = (data) => {
  const descSchema = Joi.object({
    question: Joi.string().required(),
    answer: Joi.string()
      .min(3)
      .message("matn 3ta harfdan ko'p bo'lishsin")
      .max(10000)
      .message("10000tadan kam, 3tadan ko'p")
      .required(),
    is_checked: Joi.boolean().default(false),
    user_id: Joi.string().alphanum(),
    expert_id: Joi.string().alphanum(),
  });

  return descSchema.validate(data, { abortEarly: false });
};

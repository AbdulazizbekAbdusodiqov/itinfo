const Joi = require("joi");

exports.topicValidation = (data) => {
  const topicSchema = Joi.object({
    author_id: Joi.string().alphanum(),
    topic_title: Joi.string()
      .min(3)
      .message("Sarlavha 3ta harfdan ko'p bo'lishsin")
      .max(50)
      .message("50tadan kam, 3tadan ko'p bo'lsinda endi")
      .required()
      .messages({
        "string.empty": "sarlavha bo'sh bo'lishi mumkin emas",
        "any.required": "sarlavha nomi kiritilishi kerak",
      }),
    topic_text: Joi.string()
      .min(10)
      .message("matn 3ta harfdan ko'p bo'lishsin")
      .max(10000)
      .message("10000tadan kam, 3tadan ko'p")
      .required()
      .messages({
        "string.empty": "Topic bo'sh bo'lishi mumkin emas",
        "any.required": "Topic nomi kiritilishi kerak",
      }),
    is_checked: Joi.boolean().default(false),
    is_approved: Joi.boolean().default(false),
    expert_id: Joi.string().alphanum().required(),
    dict_id: Joi.string().alphanum().required(),
  });

  return topicSchema.validate(data, { abortEarly: false });
};

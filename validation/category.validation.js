const Joi = require("joi");

exports.categoryValidation = (data) => {
  const categorySchema = Joi.object({
    category_name: Joi.string()
      .min(3)
      .message("Kategoriya 3ta harfdan ko'p bo'lishsin")
      .max(50)
      .message("50tadan kam, 3tadan ko'p")
      .required()
      .messages({
        "string.empty": "kategoriya bo'sh bo'lishi mumkin emas",
        "any.required": "Kategoriya nomi kiritilishi kerak",
      }),
    parent_category_id: Joi.string().alphanum().message("ID noto'g'ri!"),
  });
  return categorySchema.validate(data, {
      abortEarly: false,
    });
};

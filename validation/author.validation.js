const Joi = require("joi");
const authorFullName = (parent) => {
  return parent.author_first_name + " " + parent.author_last_name;
};

exports.authorValidation = (data) => {
  const authorSchema = Joi.object({
    author_first_name: Joi.string().required(),
    author_last_name: Joi.string().required(),
    full_name: Joi.string().default(authorFullName),
    author_nick_name: Joi.string().pattern(
      new RegExp("^[a-zA-Z0-9!@#_]{3,30}$")
    ),
    author_email: Joi.string().email().lowercase(),
    author_phone: Joi.string().pattern(/^\d{2}-\d{3}-\d{2}-\d{2}$/),
    author_password: Joi.string().pattern(new RegExp("^[a-zA-Z0-9]{3,30}$")),
    // confirm_author_password: Joi.ref("author_password"),
    // author_info: Joi.string(),
    author_position: Joi.string(),
    is_expert: Joi.boolean().default(false),
    author_is_active: Joi.boolean().default(false),
    // gender: Joi.string().valid("erkak", "ayol"),
    referred: Joi.boolean().default(false),
  });

  return authorSchema.validate(data, { abortEarly: false });
};

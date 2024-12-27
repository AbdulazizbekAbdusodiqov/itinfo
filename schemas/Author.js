const { Schema, model } = require("mongoose");

const authorSchema = new Schema({
  author_first_name: {
    type: String,
    required: true,
    trim: true,
  },
  author_last_name: {
    type: String,
    required: true,
    trim: true,
  },
  author_nick_name: {
    type: String,
    required: true,
    unique: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-zA-Z0-9_-]{3,20}$/,
  },
  author_email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,4})+$/,
      "Iltimos, emailni to'g'ri kiriting",
    ],
  },
  author_phone: {
    type: String,
    validate: {
      validator: function (value) {
        return /^\d{2}-\d{3}-\d{2}-\d{2}$/.test(value);
      },
      message: (props) => `${props.value} - raqam no'to'g'ri`,
    },
  },
  author_password: {
    type: String,
    required: true,
  },
  author_position: {
    type: String
  },
  is_expert: {
    type: Boolean,
    default: false
  },
  author_is_active: {
    type: Boolean,
    default: true
  },
  refresh_token: String,
  activation_link : String
});

module.exports = model("Author", authorSchema);

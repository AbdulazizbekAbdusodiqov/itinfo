const { Schema, model } = require("mongoose");

const userSchema = new Schema(
  {
    user_name: { type: String, trim: true, uppercase: true },
    user_email: {
      type: String,
      required: [true, "Emailni kiriting"],
      unique: true,
      lowercase: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,4})+$/,
        "Iltimos, to'g'ri emailni kiriting",
      ],
    },
    user_password: {
      type: String,
      required: [true, "Parolni kiriting"],
      minlength: [6, "Parol 6 ta belgidan kam bo'lmasligi kerak"],
    },
    user_info: {
      type: String,
      maxlength: [150, "Qisqa info kiriting (150 ta belgidan kam)"],
    },
    user_photo: String,
    user_is_active: {
      type: Boolean,
      defaultValue: false,
    },
    refresh_token: String,
    activation_link: String

  },
  {
    versionKey: false,
    timestamps: true,
    toJSON: {
      getters: true,
    },
  }
);

userSchema.statics.findByEmail = function (email) {
  return this.findOne({ user_email: new RegExp(email, "i") });
};

userSchema.query.byEmail = function (email) {
  return this.where({ user_email: new RegExp(email, "i") });
};

module.exports = model("User", userSchema);

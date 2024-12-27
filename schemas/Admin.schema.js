const { Schema, model } = require("mongoose");

const adminSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Admin name is required"],
      trim: true,
      minLength: [3, "Admin name must be at least 3 characters"],
      maxLength: [50, "Admin name cannot exceed 50 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,4})+$/,
        "Please provide a valid email address",
      ],
    },
    phone: {
      type: String,
      validate: {
        validator: function (value) {
          return /^\d{2}-\d{3}-\d{2}-\d{2}$/.test(value);
        },
        message: (props) => `${props.value}-raqam noto'g'ri`,
      },
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minLength: [6, "Password must be at least 6 characters long"],
    },
    is_active: {
      type: Boolean,
      default: true,
    },
    is_creator: {
      type: Boolean,
      default: false,
    },
    created_date: {
      type: Date,
      default: Date.now,
      immutable: true,
    },
    updated_date: {
      type: Date,
      default: Date.now,
    },
    refresh_token: String,
  },
  {
    timestamps: { createdAt: "created_date", updatedAt: "updated_date" },
    versionKey: false,
  }
);

module.exports = model("Admin", adminSchema);
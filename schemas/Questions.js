const { Schema, model } = require("mongoose");

const questionSchema = new Schema(
  {
    question: {
      type: String,
      required: [true, "Savol kiritilishi shart"],
      trim: true,
    },
    answer: {
      type: String,
      default: "", 
      trim: true,
    },
    created_date: {
      type: Date,
      default: Date.now,
    },
    updated_date: {
      type: Date, 
    },
    is_checked: {
      type: Boolean,
      default: false, 
    },
    user_id: {
      type: Schema.Types.ObjectId,
      ref: "User", 
      required: [true, "Foydalanuvchi ID kiritilishi shart"],
    },
    expert_id: {
      type: Schema.Types.ObjectId,
      ref: "Author", 
    },
  },
  {
    timestamps: false, 
  }
);

module.exports = model("Question", questionSchema);

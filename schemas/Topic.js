const { Schema, model } = require("mongoose");

const topicSchema = new Schema(
  {
    author_id: {
      type: Schema.Types.ObjectId, 
      ref: "Author", 
      required: true,
    },
    topic_title: {
      type: String,
      required: true,
      minlength: [5, "Sarlavha kamida 5ta belgidan iborat bo'lishi kerak"],
      maxlength: [100, "Sarlavha 100ta belgidan oshmasligi kerak"],
      trim: true,
    },
    topic_text: {
      type: String,
      required: true,
      minlength: [10, "Matn kamida 10ta belgidan iborat bo'lishi kerak"],
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
    is_approved: {
      type: Boolean,
      default: false, 
    },
    expert_id: {
      type: Schema.Types.ObjectId,
      ref: "Expert", 
    },
  },
  { timestamps: true } 
);

module.exports = model("Topic", topicSchema);

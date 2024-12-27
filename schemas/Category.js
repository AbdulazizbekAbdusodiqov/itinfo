const { Schema, model } = require("mongoose");

const categorySchema = new Schema({
  category_name: {
    type: String,
    required: true,
    trim: true,
  },
  parent_category_id: { type: Schema.Types.ObjectId, ref: "Category" },
});

module.exports = model("Category", categorySchema);

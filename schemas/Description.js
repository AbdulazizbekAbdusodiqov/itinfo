const { required } = require("joi");
const { Schema, model } = require("mongoose");

const descSchema = new Schema({
  category_id: {
    type: Schema.Types.ObjectId,
    ref: "Category",
  },
  description: { type: String, unique: true, required: true },
});

module.exports = model("Description", descSchema);

const { required } = require("joi");
const { Schema, model } = require("mongoose");

const descQASchema = new Schema({
  qa_id: {
    type: Schema.Types.ObjectId,
    ref: "Questions",
  },
  desc_id: {
    type: Schema.Types.ObjectId,
    ref: "Description",
  },
});

module.exports = model("DescriptionQA", descQASchema);

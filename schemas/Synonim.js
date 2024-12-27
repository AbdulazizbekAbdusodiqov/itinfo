const { Schema, model } = require("mongoose");

const synSchema = new Schema({
  desc_id: {
    type: Schema.Types.ObjectId,
    ref: "Description",
  },
  dict_id: { type: Schema.Types.ObjectId, ref: "Dictionary" },
});

module.exports = model("Synonim", synSchema);

const { Schema, model } = require("mongoose");

const socialSchema = new Schema({
  social_name: {
    type: String,
    required: [true, "Ijtimoiy tarmoq nomini kiriting"],
    trim: true,
  },
  social_icon_file: {
    type: String,
    required: [true, "Ijtimoiy tarmoq ikonasini yuklang"],
  },
});

module.exports = model("Social", socialSchema);

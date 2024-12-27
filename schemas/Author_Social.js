const { Schema, model } = require("mongoose");

const authorSocialSchema = new Schema({
  author_id: {
    type: Schema.Types.ObjectId,
    required: [true, "Muallif ID sini kiriting"],
    ref: "Author",
  },
  social_id: {
    type: Schema.Types.ObjectId,
    required: [true, "Ijtimoiy tarmoq ID sini kiriting"],
    ref: "Social",
  },
  social_link: {
    type: String,
    required: [true, "Ijtimoiy tarmoq havolasini kiriting"],
    match: [
      /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/,
      "To'g'ri URL formatini kiritishingiz k/k",
    ],
  },
});

module.exports = model("AuthorSocial", authorSocialSchema);

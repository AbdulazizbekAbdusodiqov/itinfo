const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Author_Social = require("../schemas/Author_Social");

const getAuthorSocials = async (req, res) => {
  try {
    const authorSocials = await Author_Social.find()
      .populate("author_id", "author_first_name author_last_name")
      .populate("social_id", "social_name social_icon_file");

    res.send({ authorSocials });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getAuthorSocialById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "ID noto'g'ri" });
    }

    const authorSocial = await Author_SocialfindOne({ _id: id })
      .populate("author_id", "author_first_name author_last_name")
      .populate("social_id", "social_name social_icon_file");

    if (!authorSocial) {
      return res
        .status(400)
        .send({ message: "Bunday ijtimoiy tarmoq mavjud emas" });
    }

    res.send({ authorSocial });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addAuthorSocial = async (req, res) => {
  try {
    const { author_id, social_id, social_link } = req.body;

    const newAuthorSocial = await Author_Socialcreate({
      author_id,
      social_id,
      social_link,
    });

    res.status(201).send({
      message: "Muallif ijtimoiy tarmog'i qo'shildi",
      newAuthorSocial,
    });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteAuthorSocialById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "ID noto'g'ri" });
    }

    const authorSocial = await Author_SocialdeleteOne({ _id: id });

    if (!authorSocial.deletedCount) {
      return res
        .status(400)
        .send({ message: "Ijtimoiy tarmoq topilmadi yoki o'chirilmagan" });
    }

    res.send({ message: "Muallif ijtimoiy tarmog'i o'chirildi" });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateAuthorSocial = async (req, res) => {
  try {
    const id = req.params.id;
    const { author_id, social_id, social_link } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "ID noto'g'ri" });
    }

    const authorSocial = await Author_Social.updateOne(
      { _id: id },
      {
        author_id,
        social_id,
        social_link,
      }
    );

    if (!authorSocial.nModified) {
      return res
        .status(400)
        .send({ message: "Muallif ijtimoiy tarmog'i yangilanmadi" });
    }

    res.send({ message: "Muallif ijtimoiy tarmog'i yangilandi", authorSocial });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getAuthorSocials,
  getAuthorSocialById,
  addAuthorSocial,
  deleteAuthorSocialById,
  updateAuthorSocial,
};

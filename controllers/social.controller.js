const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Social = require("../schemas/Social");
const {socialValidation} = require("../validation/social.validation")


const getSocials = async (req, res) => {
  try {
    const socials = await Social.find();
    res.send({ socials });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getSocialById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "ID noto'g'ri" });
    }

    const social = await Social.findOne({ _id: id });

    if (!social) {
      return res
        .status(400)
        .send({ message: "Bunday ijtimoiy tarmoq mavjud emas" });
    }

    res.send({ social });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addSocial = async (req, res) => {
  try {
    const {error,value} = socialValidation(req.body);
    if(error){
      return res.status(400).send({message:error.message})
    }
    const { social_name, social_icon_file } = req.body;

    const newSocial = await Social.create({
      social_name,
      social_icon_file,
    });

    res
      .status(201)
      .send({ message: "Yangi ijtimoiy tarmoq qo'shildi", newSocial });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteSocialById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "ID noto'g'ri" });
    }

    const social = await Social.deleteOne({ _id: id });

    if (!social.deletedCount) {
      return res
        .status(400)
        .send({ message: "Ijtimoiy tarmoq topilmadi yoki o'chirilmagan" });
    }

    res.send({ message: "Ijtimoiy tarmoq o'chirildi" });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateSocial = async (req, res) => {
  try {
    const id = req.params.id;
    const { social_name, social_icon_file } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "ID noto'g'ri" });
    }

    const social = await Social.updateOne(
      { _id: id },
      {
        social_name,
        social_icon_file,
      }
    );

    if (!social.nModified) {
      return res.status(400).send({ message: "Ijtimoiy tarmoq yangilanmadi" });
    }

    res.send({ message: "Ijtimoiy tarmoq yangilandi", social });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getSocials,
  getSocialById,
  addSocial,
  deleteSocialById,
  updateSocial,
};

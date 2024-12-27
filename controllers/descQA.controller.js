const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const DescriptionQA = require("../schemas/DescQA");
const { descQAValidation } = require("../validation/descQA.validation");

const getDescriptionsQA = async (req, res) => {
  try {
    const descriptionsQA = await DescriptionQA.find()
      .populate("qa_id", "question_text")
      .populate("desc_id", "description_text");

    res.send({ descriptionsQA });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getDescriptionQAById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const descriptionQA = await DescriptionQA.findOne({ _id: id })
      .populate("qa_id", "question_text")
      .populate("desc_id", "description_text");

    if (!descriptionQA) {
      return res
        .status(404)
        .send({ message: "Bunday descriptionQA mavjud emas" });
    }

    res.send({ descriptionQA });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addDescriptionQA = async (req, res) => {
  try {
    const { qa_id, desc_id } = req.body;

    const { error } = descQAValidation(req.body);
    if (error) {
      return res.status(400).send({ message: error.message });
    }

    const newDescriptionQA = await DescriptionQA.create({
      qa_id,
      desc_id,
    });

    res.status(201).send({
      message: "Yangi DescriptionQA qo'shildi",
      newDescriptionQA,
    });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteDescriptionQAById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const deletedDescriptionQA = await DescriptionQA.deleteOne({ _id: id });

    res.send({
      message: "DescriptionQA o'chirildi",
      deletedDescriptionQA,
    });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateDescriptionQA = async (req, res) => {
  try {
    const id = req.params.id;
    const { qa_id, desc_id } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const updatedDescriptionQA = await DescriptionQA.updateOne(
      { _id: id },
      { qa_id, desc_id }
    );

    res.send({
      message: "DescriptionQA yangilandi",
      updatedDescriptionQA,
    });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getDescriptionsQA,
  getDescriptionQAById,
  addDescriptionQA,
  deleteDescriptionQAById,
  updateDescriptionQA,
};

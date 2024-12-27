const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Description = require("../schemas/Description");
const { descValidation } = require("../validation/desc.validation");

const getDescriptions = async (req, res) => {
  try {
    const descriptions = await Description.find().populate(
      "category_id",
      "category_name"
    );
    res.send({ descriptions });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getDescriptionById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const description = await Description.findOne({ _id: id }).populate(
      "category_id",
      "category_name"
    );

    if (!description) {
      return res
        .status(400)
        .send({ message: "Bunday description mavjud emas" });
    }

    res.send({ description });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addDescription = async (req, res) => {
  try {
    const { category_id, description } = req.body;

    const { error, value } = descValidation(req.body);
    if (error) {
      return res.status(400).send({ message: error.message });
    }
    const newDescription = await Description.create({
      category_id,
      description,
    });
    res.status(201).send({ message: "New description added", newDescription });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteDescriptionById = async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const description = await Description.deleteOne({ _id: id });
    res.send({ description });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateDescription = async (req, res) => {
  try {
    const id = req.params.id;
    const { category_id, description } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const descriptionUpdate = await Description.updateOne(
      { _id: id },
      { category_id, description }
    );
    res.send({ descriptionUpdate });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getDescriptions,
  addDescription,
  getDescriptionById,
  deleteDescriptionById,
  updateDescription,
};

const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Tag = require("../schemas/Tag");

const getTags = async (req, res) => {
  try {
    const tags = await Tag.find()
      .populate("topic_id", "topic_name")
      .populate("category_id", "category_name");
    res.send({ tags });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getTagById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const tag = await Tag.findOne({ _id: id })
      .populate("topic_id", "topic_name")
      .populate("category_id", "category_name");

    if (!tag) {
      return res.status(400).send({ message: "Bunday tag mavjud emas" });
    }

    res.send({ tag });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addTag = async (req, res) => {
  try {
    const { topic_id, category_id } = req.body;

    const newTag = await Tag.create({ topic_id, category_id });

    res.status(201).send({ message: "New tag added", newTag });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteTagById = async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const tag = await Tag.deleteOne({ _id: id });
    res.send({ tag });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateTag = async (req, res) => {
  try {
    const id = req.params.id;
    const { topic_id, category_id } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const tag = await Tag.updateOne(
      { _id: id },
      {
        topic_id,
        category_id,
      }
    );
    res.send({ tag });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getTags,
  addTag,
  getTagById,
  deleteTagById,
  updateTag,
};

const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Topic = require("../schemas/Topic");

const getTopics = async (req, res) => {
  try {
    const topics = await Topic.find()
      // .populate("author_id", "author_first_name author_last_name")
      // .populate("expert_id", "author_first_name author_last_name");
    res.send({ topics });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getTopicById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const topic = await Topic.findOne({ _id: id })
      .populate("author_id", "author_first_name author_last_name")
      .populate("expert_id", "author_first_name author_last_name");

    if (!topic) {
      return res.status(400).send({ message: "Bunday mavzu mavjud emas" });
    }

    res.send({ topic });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addTopic = async (req, res) => {
  try {
    const {
      author_id,
      topic_title,
      topic_text,
      expert_id,
      is_checked,
      is_approved,
    } = req.body;

    const newTopic = await Topic.create({
      author_id,
      topic_title,
      topic_text,
      expert_id,
      is_checked,
      is_approved,
    });

    res.status(201).send({ message: "Yangi mavzu qo'shildi", newTopic });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteTopicById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const topic = await Topic.deleteOne({ _id: id });

    if (!topic.deletedCount) {
      return res
        .status(400)
        .send({ message: "Mavzu topilmadi yoki o'chirilmagan" });
    }

    res.send({ message: "Mavzu o'chirildi" });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateTopic = async (req, res) => {
  try {
    const id = req.params.id;
    const { topic_title, topic_text, expert_id, is_checked, is_approved } =
      req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const topic = await Topic.updateOne(
      { _id: id },
      {
        topic_title,
        topic_text,
        expert_id,
        is_checked,
        is_approved,
        updated_date: Date.now(),
      }
    );

    if (!topic.nModified) {
      return res.status(400).send({ message: "Mavzu yangilanmadi" });
    }

    res.send({ message: "Mavzu yangilandi", topic });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getTopics,
  getTopicById,
  addTopic,
  deleteTopicById,
  updateTopic,
};

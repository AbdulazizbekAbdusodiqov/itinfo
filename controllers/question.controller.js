const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Question = require("../schemas/Questions");
const { questionValidation } = require("../validation/question.validation");

const getQuestions = async (req, res) => {
  try {
    const questions = await Question.find()
      .populate("user_id", "name email")
      .populate("expert_id", "author_first_name author_last_name");

    res.send({ questions });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getQuestionById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const question = await Question.findOne({ _id: id })
      .populate("user_id", "name email")
      .populate("expert_id", "author_first_name author_last_name");

    if (!question) {
      return res.status(400).send({ message: "Bunday savol mavjud emas" });
    }

    res.send({ question });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addQuestion = async (req, res) => {
  try {
    const { question, answer, user_id, expert_id, is_checked } = req.body;

    const { error, value } = descValidation(req.body);
    if (error) {
      return res.status(400).send({ message: error.message });
    }

    const newQuestion = await Question.create({
      question,
      answer,
      user_id,
      expert_id,
      is_checked,
    });

    res.status(201).send({ message: "Yangi savol qo'shildi", newQuestion });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteQuestionById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const question = await Question.deleteOne({ _id: id });

    if (!question.deletedCount) {
      return res
        .status(400)
        .send({ message: "Savol topilmadi yoki o'chirilmagan" });
    }

    res.send({ message: "Savol o'chirildi" });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateQuestion = async (req, res) => {
  try {
    const id = req.params.id;
    const { question, answer, is_checked, expert_id } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const updatedQuestion = await Question.updateOne(
      { _id: id },
      {
        question,
        answer,
        is_checked,
        expert_id,
        updated_date: Date.now(),
      }
    );

    if (!updatedQuestion.nModified) {
      return res.status(400).send({ message: "Savol yangilanmadi" });
    }

    res.send({ message: "Savol yangilandi", updatedQuestion });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getQuestions,
  getQuestionById,
  addQuestion,
  deleteQuestionById,
  updateQuestion,
};

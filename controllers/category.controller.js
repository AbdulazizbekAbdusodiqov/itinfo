const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Joi = require("joi");
const Category = require("../schemas/Category");
const { categoryValidation } = require("../validation/category.validation");

const getCategories = async (req, res) => {
  try {
    const categories = await Category.find().populate(
      "parent_category_id",
      "category_name"
    );
    res.send({ categories });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getCategoryById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const category = await Category.findById(id);
    if (!category) {
      return res.status(400).send({ message: "Bunday kategoriya mavjud emas" });
    }

    res.send({ category });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addCategory = async (req, res) => {
  try {
    const {error, value} = categoryValidation(req.body);

    if (error) {
      return res.status(400).send({ message: error.message });
    }

    const { category_name, parent_category_id } = value;

    // const lastCategory = await Category.findOne().sort({ createdAt: -1 });

    const newCategory = await Category.create({
      category_name,
      parent_category_id: lastCategory ? lastCategory._id : null,
    });

    const populatedCategory = await Category.findById(newCategory._id).populate(
      "parent_category_id",
      "category_name"
    );

    res
      .status(201)
      .send({ message: "New category added", newCategory: populatedCategory });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteCategoryById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: " Id noto'g'ri" });
    }

    const category = await Category.findByIdAndDelete(id);
    if (!category) {
      return res.status(400).send({ message: "Category not found" });
    }

    res.send({ message: "Category deleted", category });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateCategory = async (req, res) => {
  try {
    const id = req.params.id;
    const { category_name, parent_category_id } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const updatedCategory = await Category.findByIdAndUpdate(
      id,
      { category_name, parent_category_id },
      { new: true }
    );

    if (!updatedCategory) {
      return res.status(400).send({ message: "Category not found" });
    }

    res.send({ message: "Category updated", updatedCategory });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getCategories,
  addCategory,
  getCategoryById,
  deleteCategoryById,
  updateCategory,
};

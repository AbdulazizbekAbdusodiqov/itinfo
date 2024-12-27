const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Dictionary = require("../schemas/Dictionary");
const { dictValiadation } = require("../validation/dict.validation");

const getDict = async (req, res) => {
  try {
    const dicts = await Dictionary.find();
    res.send({ dicts });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getDictById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const term = await Dictionary.findOne({ _id: id }, { term: 1 });
    if (!term) {
      return res.status(400).send({ message: "Bunday termin mavjud emas" });
    }

    res.send({ term });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addTerm = async (req, res) => {
  try {
    const { term } = req.body;


    const { error, value } = dictValiadation(req.body);
    if (error) {
      return res.status(400).send({ message: error.message });
    }

    const oldTerm = await Dictionary.findOne({ term });
    if (oldTerm) {
      return res.status(400).send({ message: "This term already exists" });
    }

    const newTerm = await Dictionary.create({ term, letter: term[0] });
    res.status(201).send({ message: "New term added", newTerm });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteDictById = async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: " Id noto'g'ri" });
    }
    const dictionary = await Dictionary.deleteOne({ _id: id });
    console.log(dictionary);
    res.send({ dictionary });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateDict = async (req, res) => {
  try {
    const id = req.params.id;
    const { term } = req.body;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: " Id noto'g'ri" });
    }
    const dictionary = await Dictionary.updateOne(
      { _id: id },
      {
        term
      }
    );
    console.log(dictionary);
    res.send({ dictionary });
  } catch (error) {
    console.log(error);
    res.status(500).send({ error: "Serverda xatolik" });
  }
};


module.exports = {
  getDict,
  addTerm,
  getDictById,
  deleteDictById,
  updateDict
};

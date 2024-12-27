const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const Synonim = require("../schemas/Synonim");

const getSynonims = async (req, res) => {
  try {
    const synonims = await Synonim.find()
      .populate("desc_id", "description") 
      .populate("dict_id", "term"); 
    res.send({ synonims });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getSynonimById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const synonim = await Synonim.findOne({ _id: id })
      .populate("desc_id", "description")
      .populate("dict_id", "term");

    if (!synonim) {
      return res.status(400).send({ message: "Bunday sinonim mavjud emas" });
    }

    res.send({ synonim });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addSynonim = async (req, res) => {
  try {
    const { desc_id, dict_id } = req.body;

    const newSynonim = await Synonim.create({ desc_id, dict_id });

    res.status(201).send({ message: "New synonim added", newSynonim });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteSynonimById = async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const synonim = await Synonim.deleteOne({ _id: id });
    res.send({ synonim });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateSynonim = async (req, res) => {
  try {
    const id = req.params.id;
    const { desc_id, dict_id } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const synonim = await Synonim.updateOne(
      { _id: id },
      {
        desc_id,
        dict_id,
      }
    );
    res.send({ synonim });
  } catch (error) {
    errorHandler(error, res);
  }
};

module.exports = {
  getSynonims,
  addSynonim,
  getSynonimById,
  deleteSynonimById,
  updateSynonim,
};

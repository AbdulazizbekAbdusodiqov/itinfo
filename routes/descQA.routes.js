const { getDescriptionsQA, addDescriptionQA, getDescriptionQAById, deleteDescriptionQAById, updateDescriptionQA } = require("../controllers/descQA.controller");

const router = require("express").Router();

router.get("/all", getDescriptionsQA);
router.post("/create", addDescriptionQA);
router.get("/:id", getDescriptionQAById);
router.delete("/:id", deleteDescriptionQAById);
router.put("/:id", updateDescriptionQA);

module.exports = router;

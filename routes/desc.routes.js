const {
  getDescriptions,
  addDescription,
  getDescriptionById,
  deleteDescriptionById,
  updateDescription,
} = require("../controllers/desc.controller");

const router = require("express").Router();

router.get("/all", getDescriptions);
router.post("/create", addDescription);
router.get("/:id", getDescriptionById);
router.delete("/:id", deleteDescriptionById);
router.put("/:id", updateDescription);

module.exports = router;

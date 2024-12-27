const {
  getTags,
  addTag,
  getTagById,
  deleteTagById,
  updateTag,
} = require("../controllers/tag.controller");

const router = require("express").Router();

router.get("/all", getTags);
router.post("/create", addTag);
router.get("/:id", getTagById);
router.delete("/:id", deleteTagById);
router.put("/:id", updateTag);

module.exports = router;

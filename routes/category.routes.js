// const { activateAuthor } = require("../controllers/author.controller");
const {
  getCategories,
  addCategory,
  getCategoryById,
  deleteCategoryById,
  updateCategory,
} = require("../controllers/category.controller");

const router = require("express").Router();

router.get("/all", getCategories);
router.post("/create", addCategory);
router.get("/:id", getCategoryById);
router.delete("/:id", deleteCategoryById);
router.put("/:id", updateCategory);

module.exports = router;

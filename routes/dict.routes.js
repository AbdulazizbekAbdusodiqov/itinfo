const {
  addTerm,
  getDictById,
  getDict,
  deleteDictById,
  updateDict,
} = require("../controllers/dict.controller");

const router = require("express").Router();

router.get("/all", getDict);
router.post("/create", addTerm);
router.get("/:id", getDictById);
router.delete("/:id", deleteDictById);
router.put("/:id", updateDict);

module.exports = router;

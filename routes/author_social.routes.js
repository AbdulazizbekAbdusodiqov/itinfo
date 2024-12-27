const {
  getAuthorSocialById,
  addAuthorSocial,
  deleteAuthorSocialById,
  updateAuthorSocial,
} = require("../controllers/author_social.controller");

const router = require("express").Router();

router.get("/all", getAuthorSocialById);
router.post("/create");
router.get("/:id", addAuthorSocial);
router.delete("/:id", deleteAuthorSocialById);
router.put("/:id", updateAuthorSocial);

module.exports = router;

const {
  getAuthors,
  addAuthor,
  getAuthorById,
  deleteAuthorById,
  updateAuthor,
  loginAuthor,
  logoutAuthor,
  refreshAuthorToken,
  activateAuthor,
} = require("../controllers/author.controller");

const authorPolice = require("../police_middleware/author_police");
const authorSelfPolice = require("../police_middleware/author_self_police");

const router = require("express").Router();

router.get("/all", getAuthors);  //authorPolice
router.get("/activate/:link", activateAuthor);
router.post("/create", addAuthor);
router.post("/login", loginAuthor);
router.post("/logout", logoutAuthor);
router.post("/refresh", refreshAuthorToken);
router.get("/:id",authorPolice,authorSelfPolice, getAuthorById);
router.delete("/:id", deleteAuthorById);
router.put("/:id", updateAuthor);

module.exports = router;

const {
  getSocials,
  addSocial,
  getSocialById,
  deleteSocialById,
  updateSocial,
} = require("../controllers/social.controller");

const router = require("express").Router();

router.get("/all", getSocials);
router.post("/create", addSocial);
router.get("/:id", getSocialById);
router.delete("/:id", deleteSocialById);
router.put("/:id", updateSocial);

module.exports = router;

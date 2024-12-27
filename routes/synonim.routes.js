const { getSynonims, addSynonim, getSynonimById, deleteSynonimById, updateSynonim } = require("../controllers/synonim.controller");

const router = require("express").Router();

router.get("/all", getSynonims);
router.post("/create", addSynonim);
router.get("/:id", getSynonimById);
router.delete("/:id", deleteSynonimById);
router.put("/:id", updateSynonim);

module.exports = router;

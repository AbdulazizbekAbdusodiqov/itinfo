const { getQuestions, addQuestion, getQuestionById, deleteQuestionById, updateQuestion } = require("../controllers/question.controller");

const router = require("express").Router();

router.get("/all", getQuestions);
router.post("/create", addQuestion);
router.get("/:id", getQuestionById);
router.delete("/:id", deleteQuestionById);
router.put("/:id", updateQuestion);

module.exports = router;

const { getTopics, addTopic, deleteTopicById, getTopicById, updateTopic } = require("../controllers/topic.controller");

const router = require("express").Router();

router.get("/all", getTopics);
router.post("/create", addTopic);
router.get("/:id", getTopicById);
router.delete("/:id", deleteTopicById);
router.put("/:id", updateTopic);

module.exports = router;

const router = require("express").Router();

const DictionaryRoute = require("./dict.routes");
const SynonimRoute = require("./synonim.routes");
const DescriptionRoute = require("./desc.routes");
const CategoryRoute = require("./category.routes");
const authorRoute = require("./author.routes");
const tagRoute = require("./tag.routes");
const usersRoute = require("./users.routes");
const questionRoute = require("./questions.routes");
const topicRoute = require("./topic.routes");
const socialRoute = require("./social.routes");
const authorSocialRoute = require("./author_social.routes");
const descQARoute = require("./descQA.routes");
const adminRouter = require("./admin.routes");

router.use("/dictionary", DictionaryRoute);
router.use("/synonim", SynonimRoute);
router.use("/description", DescriptionRoute);
router.use("/category", CategoryRoute);
router.use("/author", authorRoute);
router.use("/users", usersRoute);
router.use("/tags", tagRoute);
router.use("/ques", questionRoute);
router.use("/topics", topicRoute);
router.use("/socials", socialRoute);
router.use("/authorsocials", authorSocialRoute);
router.use("/descqa", descQARoute);
router.use("/admin", adminRouter);

module.exports = router;

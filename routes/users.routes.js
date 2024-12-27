const {
  getUsers,
  addUser,
  getUserById,
  deleteUserById,
  updateUser,
  loginUser,
  activateUser
} = require("../controllers/user.controller");


const userPolice = require("../police_middleware/user.police");
const userSelfPolice = require("../police_middleware/user.self.police");

const router = require("express").Router();

router.get("/all", userPolice,getUsers); 
router.get("/activate/:link", activateUser); 
router.post("/create", addUser); 
router.post("/login", loginUser);
router.get("/:id",userPolice, userSelfPolice, getUserById);
router.delete("/:id", deleteUserById);
router.put("/:id", updateUser); 



module.exports = router;


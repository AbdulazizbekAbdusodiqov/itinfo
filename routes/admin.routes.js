const {
    addAdmin,
    getById,
    updateById,
    deleteById,
    getAllAdmin,
    logoutAdmin,
    loginAdmin,
    refreshAdminToken
  } = require("../controllers/admin.controller");
  const adminPolice = require("../police_middleware/admin.police");
  const adminSelfPolice = require("../police_middleware/admin.self.police");
  
  const router = require("express").Router();
  
  router.get("/all", getAllAdmin); 
  router.post("/create", addAdmin); 
  router.post("/login", loginAdmin); 
  router.post("/logout", logoutAdmin);
  router.post("/refresh", refreshAdminToken);
  router.get("/:id",adminPolice, adminSelfPolice, getById);
  router.delete("/:id", deleteById);
  router.put("/:id", updateById); 
  
  module.exports = router;
  
  
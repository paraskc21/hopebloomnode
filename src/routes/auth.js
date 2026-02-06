const express = require("express");

const auth = require("../middleware/auth");
const { createUser, loginUser, getProfile, assignAdminRole, getAllUsers } = require("../controller/user.controller");

const router = express.Router();

// REGISTER
router.post("/register", createUser);

// LOGIN
router.post("/login", loginUser);

// PROTECTED ROUTE (any logged-in user)
router.get("/profile", auth(), getProfile);

// ADMIN ONLY
router.get("/admin", auth(["admin"]), (req, res) => {
  res.json({
    success: true,
    message: "Admin access granted",
    user: req.user,
  });
});

// SUPERUSER ONLY - Assign admin role
router.post("/assign-admin", auth(["superuser"]), assignAdminRole);

// SUPERUSER ONLY - Get all users
router.get("/users", auth(["superuser"]), getAllUsers);

module.exports = router;

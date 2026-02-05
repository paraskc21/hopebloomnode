const express = require("express");

const auth = require("../middleware/auth");
const { createUser, loginUser, getProfile } = require("../controller/user.controller");

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

module.exports = router;

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

/**
 * Validate register input
 */
function validateRegister(body) {
  const { username, password, role } = body;
  const errors = [];

  if (!username || typeof username !== "string") {
    errors.push("Username is required");
  } else {
    const trimmed = username.trim();
    if (trimmed.length < 3) errors.push("Username must be at least 3 characters");
    if (trimmed.length > 64) errors.push("Username must be at most 64 characters");
  }

  if (!password || typeof password !== "string") {
    errors.push("Password is required");
  } else {
    if (password.length < 6) errors.push("Password must be at least 6 characters");
    if (password.length > 128) errors.push("Password must be at most 128 characters");
  }

  if (role !== undefined && role !== null && role !== "") {
    const allowed = ["user", "admin", "doctor"];
    if (!allowed.includes(String(role).toLowerCase())) {
      errors.push("Role must be one of: user, admin, doctor");
    }
  }

  return errors;
}

/**
 * Validate login input
 */
function validateLogin(body) {
  const { username, password } = body;
  const errors = [];

  if (!username || typeof username !== "string" || !username.trim()) {
    errors.push("Username is required");
  }

  if (!password || typeof password !== "string") {
    errors.push("Password is required");
  }

  return errors;
}

/**
 * POST /api/auth/register
 * Create a new user (sign up)
 */
async function createUser(req, res) {
  try {
    const validationErrors = validateRegister(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: validationErrors[0],
        errors: validationErrors,
      });
    }

    const { username, password, role, name, phone, specialization, licenseNumber } = req.body;
    const trimmedUsername = username.trim().toLowerCase();
    const normalizedRole = role ? String(role).toLowerCase() : "user";
    const allowedRoles = ["user", "admin", "doctor"];
    const finalRole = allowedRoles.includes(normalizedRole) ? normalizedRole : "user";

    const existing = await User.findOne({ username: trimmedUsername });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: "Username already registered",
      });
    }

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({
      username: trimmedUsername,
      password: hashed,
      role: finalRole,
      name: name || "",
      phone: phone || "",
      specialization: specialization || "",
      licenseNumber: licenseNumber || "",
    });
    await user.save();

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        name: user.name,
        phone: user.phone,
        specialization: user.specialization,
        licenseNumber: user.licenseNumber,
      },
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "Username already registered",
      });
    }
    console.error("Register error:", err);
    res.status(500).json({
      success: false,
      message: "Registration failed. Please try again.",
    });
  }
}

/**
 * POST /api/auth/login
 * Authenticate user and return JWT
 */
async function loginUser(req, res) {
  try {
    const validationErrors = validateLogin(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: validationErrors[0],
        errors: validationErrors,
      });
    }

    const { username, password } = req.body;
    const trimmedUsername = username.trim().toLowerCase();

    const user = await User.findOne({ username: trimmedUsername }).select("+password");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    const userResponse = {
      id: user._id,
      username: user.username,
      role: user.role,
    };

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: userResponse,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({
      success: false,
      message: "Login failed. Please try again.",
    });
  }
}

/**
 * GET /api/auth/profile (protected)
 * Get current user profile (called from route with req.user set by auth middleware)
 */
async function getProfile(req, res) {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }
    res.json({
      success: true,
      message: "Welcome to your profile",
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        name: user.name,
        phone: user.phone,
        specialization: user.specialization,
        licenseNumber: user.licenseNumber,
      },
    });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to load profile",
    });
  }
}

module.exports = {
  createUser,
  loginUser,
  getProfile,
};

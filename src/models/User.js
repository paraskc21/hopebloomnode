const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
      lowercase: true,
      minlength: [3, "Username must be at least 3 characters"],
      maxlength: [64, "Username must be at most 64 characters"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
      select: false, // exclude from find() by default; use .select('+password') when needed
    },
    role: {
      type: String,
      enum: { values: ["user", "admin", "doctor"], message: "Role must be user, admin, or doctor" },
      default: "user",
    },
    name: {
      type: String,
      trim: true,
    },
    phone: {
      type: String,
      trim: true,
    },
    specialization: {
      type: String,
      trim: true,
    },
    licenseNumber: {
      type: String,
      trim: true,
    },
  },
  { timestamps: true }
);

// Index for faster login lookups
UserSchema.index({ username: 1 });

module.exports = mongoose.model("User", UserSchema);

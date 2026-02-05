/**
 * Seed demo users for HopeBloom.
 * Run: node src/scripts/seed.js
 * Requires: MONGO_URI and JWT_SECRET in .env (JWT not used here, but dotenv loads env)
 */
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const User = require("../models/User");

const DEMO_USERS = [
  { username: "user@hopebloom.org", password: "user123", role: "user" },
  { username: "doctor@hopebloom.org", password: "doctor123", role: "doctor" },
  { username: "admin@hopebloom.org", password: "admin123", role: "admin" },
];

async function seed() {
  if (!process.env.MONGO_URI) {
    console.error("MONGO_URI not set in .env");
    process.exit(1);
  }

  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");

    for (const { username, password, role } of DEMO_USERS) {
      const existing = await User.findOne({ username }).select("+password");
      if (existing) {
        console.log(`User ${username} already exists, skipping`);
        continue;
      }
      const hashed = await bcrypt.hash(password, 12);
      await User.create({ username, password: hashed, role });
      console.log(`Created ${role}: ${username}`);
    }

    console.log("Seed completed.");
  } catch (err) {
    console.error("Seed error:", err);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

seed();

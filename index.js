require("dotenv").config();

const express = require("express");
const cors = require("cors");
const connectDB = require("./src/config/db");
const authRoutes = require("./src/routes/auth");

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;

if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET in environment. Set it in .env");
  process.exit(1);
}

if (!MONGO_URI) {
  console.error("Missing MONGO_URI in environment. Set it in .env");
  process.exit(1);
}

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/auth", authRoutes);

app.get("/api/health", (req, res) => {
  res.json({ ok: true, message: "HopeBloom API is running" });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to start server:", err);
    process.exit(1);
  });

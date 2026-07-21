require("dotenv").config();
const path = require("path");
const express = require("express");
const cors = require("cors");
const { connectDB } = require("./lib/mongoose");

const authRoutes = require("./routes/auth");
const fileRoutes = require("./routes/files");

const app = express();
app.use(cors());
app.use(express.json({ limit: "25mb" }));

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error("MongoDB connection error:", err.message);
    res.status(503).json({
      error: "Database connection failed",
      detail: err.message,
    });
  }
});

app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "reset-password.html"));
});
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);

module.exports = app;

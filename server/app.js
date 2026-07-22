require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const { connectDB } = require("./lib/mongoose");

const authRoutes = require("./routes/auth");
const fileRoutes = require("./routes/files");

const app = express();
app.use(cors());
app.use(express.json({ limit: "25mb" }));

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "reset-password.html"));
});

app.get("/open-extension", (req, res) => {
  const htmlPath = path.join(__dirname, "public", "open-extension.html");
  const html = fs
    .readFileSync(htmlPath, "utf8")
    .replace(/__EXTENSION_ID__/g, process.env.EXTENSION_ID || "");
  res.type("html").send(html);
});

app.use(express.static(path.join(__dirname, "public")));

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

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);

module.exports = app;

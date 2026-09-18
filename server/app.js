require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { connectDB } = require("./lib/mongoose");

const authRoutes = require("./routes/auth");
const fileRoutes = require("./routes/files");
const publicRoutes = require("./routes/public");
const adminRoutes = require("./routes/admin");

const app = express();

const corsOrigins = String(process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: corsOrigins.length ? corsOrigins : true,
    credentials: true,
  }),
);
app.use(cookieParser());
app.use(express.json({ limit: "40mb" }));
app.use(express.urlencoded({ extended: true, limit: "40mb" }));

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

// Google Cloud Console redirect for Gmail connect (GOOGLE_GMAIL_REDIRECT_URI).
// Must match env / authorized redirect URI, e.g. https://…/auth/google/callback
app.get("/auth/google/callback", authRoutes.handleGmailOAuthCallback);

// Public APIs first — no auth middleware on this router.
app.use("/api/public", publicRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/admin", adminRoutes);

// Express body-parser throws this before route handlers run.
app.use((err, req, res, next) => {
  if (err?.type === "entity.too.large" || err?.name === "PayloadTooLargeError") {
    return res.status(413).json({
      error:
        "File is too large for the encrypt API. Use a PDF under ~20 MB.",
      code: "PAYLOAD_TOO_LARGE",
    });
  }
  next(err);
});

module.exports = app;

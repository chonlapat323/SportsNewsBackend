const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();

// Import routes
const authRoutes = require("./routes/authRoutes");

// Middleware พื้นฐาน
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Route สำหรับทดสอบ
app.get("/api/healthcheck", (req, res) => {
  res.status(200).json({ message: "Server is up and running!" });
});

// API Routes
app.use("/api/auth", authRoutes);

module.exports = app;

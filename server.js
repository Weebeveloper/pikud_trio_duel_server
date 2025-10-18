const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 3000;

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DBNAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.get("/api/health", async (req, res) => {
  try {
    await db.promise().query("SELECT 1");
    res.status(200).send("OK");
  } catch (err) {
    console.error("Health check failed:", err);
    res.status(500).send("DB connection error");
  }
});

app.get("/api/verify-token", (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No token provided" });

    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ user });
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(403).json({ message: "Invalid token" });
  }
});

// GET user by id
app.get("/api/userById", (req, res) => {
  const id = req.query.id; // get email from query string
  if (!id) return res.status(400).json({ message: "ID is required" });

  const sql = "SELECT * FROM users WHERE id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) return res.status(500).json({ message: err.message });
    if (!results.length)
      return res.status(404).json({ message: "User not found" });
    res.json(results[0]); // return the first (and only) user
  });
});

app.get("/api/allUsers", (req, res) => {
  const excludedId = req.query.excludedId;
  if (!excludedId)
    return res.status(400).json({ message: "excludedId is required" });

  const sql = "SELECT * FROM users WHERE id <> ?";
  db.query(sql, [excludedId], (err, results) => {
    if (err) return res.status(500).json({ message: err.message });
    res.json(results); // array of users
  });
});

// Login endpoint
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password are required" });

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, result) => {
      try {
        if (err) return res.status(500).json({ message: err });
        if (result.length === 0)
          return res.status(400).json({ message: "User not found" });

        const user = result[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
          return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign(
          { id: user.id, email: user.email },
          process.env.JWT_SECRET
        );

        delete user.password;

        res.json({
          message: "Login successful",
          token,
          userId: { id: user.id },
        });
      } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    }
  );
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message });
});

app.listen(port, () => console.log(`Server running on port ${port}`));

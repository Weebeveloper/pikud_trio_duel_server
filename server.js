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

// Configure DB connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DBNAME,
});

// Connect to DB
db.connect((err) => {
  if (err) throw err;
  console.log("MySQL connected!");
});

app.get("/api/verify-token", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, "secretkey", (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    res.json({ user }); // send decoded user info
  });
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
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, result) => {
      if (err) return res.status(500).send(err);
      if (result.length === 0) return res.status(400).send("User not found");

      const user = result[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).send("Invalid credentials");

      const token = jwt.sign({ id: user.id, email: user.email }, "secretkey");

      delete user.password;

      res.json({ message: "Login successful", token, userId: { id: user.id } });
    }
  );
});

app.listen(this.port, () => console.log(`Server running on port ${this.port}`));

// Version intentionnellement vulnérable de l'application
// update

const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

const bcrypt = require("bcrypt");
const saltRounds = 10;
app.post("/register", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) throw err;
    db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hash], (err, result) => {
      if (err) throw err;
      res.json({ message: "Utilisateur enregistré avec succès" });
    });
  });
});

const secretKey = process.env.JWT_SECRET_KEY;

// Assurez-vous de définir la clé secrète dans votre environnement, par exemple dans un fichier .env
// JWT_SECRET_KEY=supersecretkey

const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limite chaque IP à 100 requêtes par fenêtre de 15 minutes
  message: "Trop de tentatives de connexion, veuillez réessayer plus tard."
});

app.use("/login", loginLimiter);

const { body, validationResult } = require('express-validator');

app.post("/login", [
  body('email').isEmail().withMessage('Email invalide'),
  body('password').isLength({ min: 6 }).withMessage('Le mot de passe doit contenir au moins 6 caractères')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  // Continue processing
});

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "users_db",
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connecté à MySQL");
});

app.get("/user", (req, res) => {
  const email = req.query.email;
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
    if (err) throw err;
    res.json(result);
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ error: "Utilisateur non trouvé" });
    }
    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ error: "Mot de passe incorrect" });
      }
      const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET_KEY);
      res.json({ token });
    });
  });
});
app.listen(3000, () =>
  console.log("Serveur vulnérable démarré sur le port 3000")
);

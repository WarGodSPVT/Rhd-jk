const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error("Set SESSION_SECRET in your environment before production deployment.");
}
app.set("trust proxy", isProduction ? 1 : false);
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

const db = new Database(process.env.DB_PATH || path.join(__dirname, "users.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: __dirname }),
  name: "app.sid",
  secret: process.env.SESSION_SECRET || "dev-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 24
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." }
});

app.use(express.static(path.join(__dirname, "public")));

function cleanIdentifier(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

app.post("/register", authLimiter, async (req, res) => {
  const identifier = cleanIdentifier(req.body.identifier);
  const password = req.body.password;

  if (!identifier || !password) {
    return res.status(400).json({ error: "Email/username and password are required." });
  }
  if (identifier.length > 254 || password.length < 12 || password.length > 128) {
    return res.status(400).json({ error: "Use an identifier under 255 characters and a password of 12–128 characters." });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      "INSERT INTO users (identifier, password_hash) VALUES (?, ?)"
    ).run(identifier, passwordHash);

    req.session.userId = Number(result.lastInsertRowid);
    req.session.identifier = identifier;
    return res.status(201).json({ user: { id: req.session.userId, identifier } });
  } catch (err) {
    if (String(err.code).includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({ error: "An account with that identifier already exists." });
    }
    console.error("Registration error:", err.message);
    return res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/login", authLimiter, async (req, res) => {
  const identifier = cleanIdentifier(req.body.identifier);
  const password = req.body.password;

  if (!identifier || typeof password !== "string" || !password) {
    return res.status(400).json({ error: "Please fill in both fields." });
  }

  try {
    const user = db.prepare(
      "SELECT id, identifier, password_hash FROM users WHERE identifier = ?"
    ).get(identifier);

    // Use a generic response to avoid revealing whether an account exists.
    const passwordOk = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!user || !passwordOk) {
      return res.status(401).json({ error: "Invalid identifier or password." });
    }

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: "Could not start a session." });
      req.session.userId = user.id;
      req.session.identifier = user.identifier;
      return res.json({ user: { id: user.id, identifier: user.identifier } });
    });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).json({ error: "Login failed due to a server error." });
  }
});

app.get("/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in." });
  res.json({ user: { id: req.session.userId, identifier: req.session.identifier } });
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Could not log out." });
    res.clearCookie("app.sid");
    res.json({ ok: true });
  });
});

app.listen(PORT, () => {
  console.log(`Login app running at http://localhost:${PORT}`);
});

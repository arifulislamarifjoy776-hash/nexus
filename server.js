
"use strict";

// ======================================
// NEXUS GAMING - NODE.JS BACKEND
// ======================================

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

// Render HTTPS reverse proxy
app.set("trust proxy", 1);
app.disable("x-powered-by");

// ======================================
// DATABASE
// ======================================

const databasePath = process.env.DATABASE_PATH ||
  path.join(__dirname, "nexus.db");

const db = new Database(databasePath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    best_score INTEGER NOT NULL DEFAULT 0,
    games_played INTEGER NOT NULL DEFAULT 0,
    total_points INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    game TEXT NOT NULL,
    score INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ======================================
// MIDDLEWARE
// ======================================

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({
  limit: "20kb"
}));

// ======================================
// SESSION CONFIGURATION
// ======================================

if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error(
    "SESSION_SECRET is required in production."
  );
}

const sessionSecret =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

app.use(session({
  name: "nexus.sid",
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// ======================================
// ORIGIN CHECK
// ======================================

app.use("/api", (req, res, next) => {
  const changingMethods = [
    "POST",
    "PUT",
    "PATCH",
    "DELETE"
  ];

  if (changingMethods.includes(req.method)) {
    const origin = req.get("origin");

    if (origin) {
      try {
        const parsed = new URL(origin);

        const expected =
          `${req.protocol}://${req.get("host")}`;

        if (parsed.origin !== expected) {
          return res.status(403).json({
            error: "Invalid request origin."
          });
        }
      } catch {
        return res.status(403).json({
          error: "Invalid request origin."
        });
      }
    }
  }

  next();
});

// ======================================
// STATIC WEBSITE
// ======================================

app.use(express.static(
  path.join(__dirname, "public")
));

// ======================================
// HELPER FUNCTIONS
// ======================================

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    bestScore: user.best_score,
    gamesPlayed: user.games_played,
    totalPoints: user.total_points
  };
}

function findUser(id) {
  return db.prepare(`
    SELECT * FROM users WHERE id = ?
  `).get(id);
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  next();
}

function validEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 72
  );
}

// ======================================
// REGISTER
// ======================================

app.post("/api/register", async (req, res) => {
  try {
    const {
      username,
      email,
      password
    } = req.body || {};

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_]{3,24}$/.test(username)
    ) {
      return res.status(400).json({
        error: "Username must be 3-24 characters."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        error: "Password must be 8-72 characters."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const existing = db.prepare(`
      SELECT id FROM users
      WHERE email = ? OR username = ?
    `).get(cleanEmail, username);

    if (existing) {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (
        username,
        email,
        password_hash
      )
      VALUES (?, ?, ?)
    `).run(username, cleanEmail, hash);

    const user = findUser(result.lastInsertRowid);

    req.session.regenerate(error => {
      if (error) {
        return res.status(500).json({
          error: "Session error."
        });
      }

      req.session.userId = user.id;

      res.status(201).json({
        message: "Registration successful.",
        user: publicUser(user)
      });
    });

  } catch (error) {
    if (error.code?.startsWith("SQLITE_CONSTRAINT")) {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    console.error(error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

// ======================================
// LOGIN
// ======================================

app.post("/api/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body || {};

    if (
      !validEmail(email) ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Invalid email or password."
      });
    }

    const user = db.prepare(`
      SELECT * FROM users
      WHERE email = ?
    `).get(email.trim().toLowerCase());

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const match = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!match) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    req.session.regenerate(error => {
      if (error) {
        return res.status(500).json({
          error: "Session error."
        });
      }

      req.session.userId = user.id;

      res.json({
        message: "Login successful.",
        user: publicUser(user)
      });
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

// ======================================
// CURRENT USER
// ======================================

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({
      user: null
    });
  }

  const user = findUser(req.session.userId);

  res.json({
    user: user ? publicUser(user) : null
  });
});

// ======================================
// LOGOUT
// ======================================

app.post("/api/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({
        error: "Logout failed."
      });
    }

    res.clearCookie("nexus.sid", {
      path: "/"
    });

    res.json({
      message: "Logged out successfully."
    });
  });
});

// ======================================
// SAVE SNAKE SCORE
// ======================================

app.post("/api/score", requireLogin, (req, res) => {
  try {
    const {
      game,
      score,
      steps,
      durationMs
    } = req.body || {};

    if (game !== "snake") {
      return res.status(400).json({
        error: "Unsupported game."
      });
    }

    if (
      !Number.isSafeInteger(score) ||
      score < 0 ||
      score > 3970 ||
      score % 10 !== 0 ||
      !Number.isSafeInteger(steps) ||
      steps < 1 ||
      steps > 100000 ||
      !Number.isSafeInteger(durationMs) ||
      durationMs < 0 ||
      score > steps * 10
    ) {
      return res.status(400).json({
        error: "Invalid score."
      });
    }

    const user = findUser(req.session.userId);

    if (!user) {
      return res.status(401).json({
        error: "User not found."
      });
    }

    const save = db.transaction(() => {
      db.prepare(`
        INSERT INTO scores (
          user_id,
          game,
          score
        )
        VALUES (?, ?, ?)
      `).run(user.id, game, score);

      db.prepare(`
        UPDATE users SET
          best_score = MAX(best_score, ?),
          games_played = games_played + 1,
          total_points = total_points + ?
        WHERE id = ?
      `).run(score, score, user.id);
    });

    save();

    res.json({
      message: "Score saved.",
      user: publicUser(findUser(user.id))
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to save score."
    });
  }
});

// ======================================
// LEADERBOARD
// ======================================

app.get("/api/leaderboard", (req, res) => {
  try {
    const players = db.prepare(`
      SELECT
        username,
        best_score AS bestScore
      FROM users
      WHERE games_played > 0
      ORDER BY best_score DESC, username ASC
      LIMIT 20
    `).all();

    res.json({
      players
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load leaderboard."
    });
  }
});

// ======================================
// HEALTH CHECK
// ======================================

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    application: "Nexus Gaming"
  });
});

// ======================================
// ERROR HANDLER
// ======================================

app.use((error, req, res, next) => {
  console.error(error);

  res.status(500).json({
    error: "Internal server error."
  });
});

// ======================================
// START SERVER
// ======================================

app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("====================================");
  console.log("    NEXUS GAMING SERVER IS RUNNING");
  console.log("====================================");
  console.log(`    PORT: ${PORT}`);
  console.log(`    http://localhost:${PORT}`);
  console.log("====================================");
  console.log("");
});

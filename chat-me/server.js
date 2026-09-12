// server.js
require("dotenv").config();
const express = require("express");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const axios = require("axios");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, "data.db"));
initDb();

// Security & middlewares
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// allow cookies to be sent; credentials:true
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(
  rateLimit({
    windowMs: 60000,
    max: 60,
  })
);

// Sessions
app.set("trust proxy", 1);
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: "./" }),
    secret: process.env.SESSION_SECRET || "replace-with-a-secure-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // true in prod behind HTTPS
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// Passport setup
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  done(null, user || null);
});

// Google strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      try {
        let user = db.prepare("SELECT * FROM users WHERE google_id = ?").get(profile.id);
        if (!user) {
          const insert = db.prepare(
            "INSERT INTO users (google_id, name, email, picture, created_at) VALUES (?, ?, ?, ?, ?)"
          );
          const info = insert.run(
            profile.id,
            profile.displayName,
            profile.emails?.[0]?.value || "",
            profile.photos?.[0]?.value || "",
            Date.now()
          );
          user = db.prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
        }
        return done(null, user);
      } catch (err) {
        console.error("Google login error:", err);
        return done(err, null);
      }
    }
  )
);

// Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

// --- Auth routes ---
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/index.html" }),
  (req, res) => {
    // store minimal session user info
    req.session.user = {
      id: req.user.id,
      name: req.user.name,
      photo: req.user.picture,
      type: "google",
    };
    // ensure session saved before redirecting
    req.session.save(() => res.redirect("/chat.html"));
  }
);

// Guest login (session-only)
app.post("/auth/guest", (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "Name required" });
  req.session.user = {
    id: `guest_${Date.now()}`,
    name: name.trim(),
    type: "guest",
  };
  req.session.save(() => res.json({ ok: true }));
});

// --- Chat API (protected by session) ---
app.post("/api/chat", async (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: "Not authenticated" });

  const { question } = req.body;
  if (!question || !question.trim()) return res.status(400).json({ error: "Question required" });

  if (!process.env.OPENROUTER_API_KEY) {
    return res.status(500).json({ error: "Server API key not configured." });
  }

  try {
    const response = await axios.post(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        model: "nvidia/nemotron-3.5-lightning:free",
        messages: [{ role: "user", content: question }],
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      }
    );

    const answer = response.data.choices?.[0]?.message?.content ?? "No answer.";

    // persist only for google users (DB)
    if (user.type === "google") {
      db.prepare(
        "INSERT INTO chats (user_id, question, answer, created_at) VALUES (?, ?, ?, ?)"
      ).run(user.id, question, answer, Date.now());
    }

    res.json({ result: answer });
  } catch (err) {
    console.error("AI request error:", err?.response?.data ?? err.message ?? err);
    res.status(502).json({ error: "Upstream AI failed" });
  }
});

// --- Get history (google: DB; guest: empty - guest uses localStorage client-side) ---
app.get("/api/history", (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: "Not authenticated" });

  if (user.type === "google") {
    const rows = db
      .prepare("SELECT id, question, answer, created_at FROM chats WHERE user_id = ? ORDER BY created_at DESC")
      .all(user.id);
    return res.json({ history: rows });
  } else {
    // guest: server doesn't persist; client should use localStorage
    return res.json({ history: [] });
  }
});

// --- Clear history endpoint (client calls /api/clear-history) ---
app.delete("/api/clear-history", (req, res) => {
  const user = req.session.user;
  if (!user || user.type !== "google") return res.status(401).json({ error: "Not authenticated" });

  db.prepare("DELETE FROM chats WHERE user_id = ?").run(user.id);
  return res.json({ ok: true });
});

// --- Logout ---
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.redirect("/index.html");
  });
});

// --- Chat page route (protect) ---
app.get("/chat.html", (req, res) => {
  if (!req.session.user) return res.redirect("/index.html");
  res.sendFile(path.join(__dirname, "public", "chat.html"));
});

// small api to fetch session user info
app.get("/api/user", (req, res) => {
  if (!req.session.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: req.session.user });
});

// fallback -> index
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT,"0.0.0.0", () => {console.log(`🚀 Chat Me running at http://localhost:${PORT}`);});

function initDb() {
  db.prepare(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      google_id TEXT UNIQUE,
      name TEXT,
      email TEXT,
      picture TEXT,
      created_at INTEGER
    )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS chats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      question TEXT,
      answer TEXT,
      created_at INTEGER
    )`
  ).run();
}

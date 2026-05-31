const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
require("dotenv").config();

const app = express();
const db = new Database("tasks.db");
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey123";

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Database Setup ────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    title       TEXT    NOT NULL,
    description TEXT    DEFAULT '',
    stage       TEXT    NOT NULL DEFAULT 'todo',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── Auth Middleware ───────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({
    success: false,
    message: "Access denied. No token provided.",
    hint: "Add 'Authorization: Bearer <token>' to your request headers."
  });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      success: false,
      message: "Invalid or expired token.",
      hint: "Please log in again to get a fresh token."
    });
  }
}

// ── API Home ──────────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({
    name: "TasKing API",
    version: "1.0.0",
    status: "🟢 Running",
    description: "Backend API for TasKing — a task manager app.",
    endpoints: {
      auth: {
        register: { method: "POST", path: "/api/register", body: { name: "string", email: "string", password: "string" } },
        login:    { method: "POST", path: "/api/login",    body: { email: "string", password: "string" } },
      },
      tasks: {
        getAll:    { method: "GET",    path: "/api/tasks",             auth: true },
        create:    { method: "POST",   path: "/api/tasks",             auth: true, body: { title: "string", description: "string (optional)", stage: "todo | inprogress | done" } },
        update:    { method: "PUT",    path: "/api/tasks/:id",         auth: true, body: { title: "string", description: "string", stage: "string" } },
        moveStage: { method: "PATCH",  path: "/api/tasks/:id/stage",   auth: true, body: { stage: "todo | inprogress | done" } },
        delete:    { method: "DELETE", path: "/api/tasks/:id",         auth: true },
      }
    },
    note: "All task routes require 'Authorization: Bearer <token>' header."
  });
});

// ── Register ──────────────────────────────────────────────────────────────────
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      message: "All fields are required.",
      missing: {
        name:     !name     ? "required" : "ok",
        email:    !email    ? "required" : "ok",
        password: !password ? "required" : "ok",
      }
    });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = db.prepare(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)"
    ).run(name, email, hashed);

    const token = jwt.sign(
      { id: result.lastInsertRowid, name, email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      success: true,
      message: `Welcome to TasKing, ${name}! Your account has been created.`,
      token,
      user: { id: result.lastInsertRowid, name, email }
    });
  } catch (err) {
    if (err.message.includes("UNIQUE")) {
      return res.status(400).json({
        success: false,
        message: "This email is already registered.",
        hint: "Try logging in instead, or use a different email."
      });
    }
    res.status(500).json({ success: false, message: "Server error. Please try again." });
  }
});

// ── Login ─────────────────────────────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required.",
      missing: {
        email:    !email    ? "required" : "ok",
        password: !password ? "required" : "ok",
      }
    });
  }

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) {
    return res.status(400).json({
      success: false,
      message: "No account found with this email.",
      hint: "Double-check your email or register a new account."
    });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(400).json({
      success: false,
      message: "Incorrect password.",
      hint: "Please check your password and try again."
    });
  }

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    success: true,
    message: `Welcome back, ${user.name}!`,
    token,
    user: { id: user.id, name: user.name, email: user.email }
  });
});

// ── GET all tasks ─────────────────────────────────────────────────────────────
app.get("/api/tasks", authMiddleware, (req, res) => {
  const tasks = db.prepare(
    "SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC"
  ).all(req.user.id);

  res.json({
    success: true,
    message: tasks.length > 0 ? `Found ${tasks.length} task(s).` : "You have no tasks yet. Create one!",
    count: tasks.length,
    tasks
  });
});

// ── POST create a task ────────────────────────────────────────────────────────
app.post("/api/tasks", authMiddleware, (req, res) => {
  const { title, description = "", stage = "todo" } = req.body;

  if (!title) {
    return res.status(400).json({
      success: false,
      message: "Task title is required."
    });
  }

  if (!["todo", "inprogress", "done"].includes(stage)) {
    return res.status(400).json({
      success: false,
      message: `Invalid stage "${stage}".`,
      hint: "Stage must be one of: todo, inprogress, done."
    });
  }

  const result = db.prepare(
    "INSERT INTO tasks (user_id, title, description, stage) VALUES (?, ?, ?, ?)"
  ).run(req.user.id, title, description, stage);

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(result.lastInsertRowid);

  res.status(201).json({
    success: true,
    message: `Task "${title}" created successfully.`,
    task
  });
});

// ── PUT update a task ─────────────────────────────────────────────────────────
app.put("/api/tasks/:id", authMiddleware, (req, res) => {
  const { title, description, stage } = req.body;
  const task = db.prepare(
    "SELECT * FROM tasks WHERE id = ? AND user_id = ?"
  ).get(req.params.id, req.user.id);

  if (!task) {
    return res.status(404).json({
      success: false,
      message: `Task with ID ${req.params.id} not found.`,
      hint: "Make sure the task exists and belongs to your account."
    });
  }

  db.prepare(
    "UPDATE tasks SET title = ?, description = ?, stage = ? WHERE id = ? AND user_id = ?"
  ).run(
    title       ?? task.title,
    description ?? task.description,
    stage       ?? task.stage,
    req.params.id,
    req.user.id
  );

  const updated = db.prepare("SELECT * FROM tasks WHERE id = ?").get(req.params.id);

  res.json({
    success: true,
    message: `Task "${updated.title}" updated successfully.`,
    task: updated
  });
});

// ── PATCH move task stage ─────────────────────────────────────────────────────
app.patch("/api/tasks/:id/stage", authMiddleware, (req, res) => {
  const { stage } = req.body;

  if (!["todo", "inprogress", "done"].includes(stage)) {
    return res.status(400).json({
      success: false,
      message: `Invalid stage "${stage}".`,
      hint: "Stage must be one of: todo, inprogress, done."
    });
  }

  const task = db.prepare(
    "SELECT * FROM tasks WHERE id = ? AND user_id = ?"
  ).get(req.params.id, req.user.id);

  if (!task) {
    return res.status(404).json({
      success: false,
      message: `Task with ID ${req.params.id} not found.`,
      hint: "Make sure the task exists and belongs to your account."
    });
  }

  db.prepare(
    "UPDATE tasks SET stage = ? WHERE id = ? AND user_id = ?"
  ).run(stage, req.params.id, req.user.id);

  const updated = db.prepare("SELECT * FROM tasks WHERE id = ?").get(req.params.id);
  const stageLabels = { todo: "Todo", inprogress: "In Progress", done: "Done" };

  res.json({
    success: true,
    message: `Task "${updated.title}" moved to ${stageLabels[stage]}.`,
    task: updated
  });
});

// ── DELETE a task ─────────────────────────────────────────────────────────────
app.delete("/api/tasks/:id", authMiddleware, (req, res) => {
  const task = db.prepare(
    "SELECT * FROM tasks WHERE id = ? AND user_id = ?"
  ).get(req.params.id, req.user.id);

  if (!task) {
    return res.status(404).json({
      success: false,
      message: `Task with ID ${req.params.id} not found.`,
      hint: "Make sure the task exists and belongs to your account."
    });
  }

  db.prepare(
    "DELETE FROM tasks WHERE id = ? AND user_id = ?"
  ).run(req.params.id, req.user.id);

  res.json({
    success: true,
    message: `Task "${task.title}" deleted successfully.`
  });
});

// ── 404 Handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.path} not found.`,
    hint: "Visit GET / to see all available endpoints."
  });
});

// ── Start Server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════╗
  ║       TasKing API is running      ║
  ║   http://localhost:${PORT}            ║
  ╚═══════════════════════════════════╝
  `);
});
const express = require("express");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT || 3000);
const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || "https://segurity-lab.netlify.app")
    .split(",").map((origin) => origin.trim()).filter(Boolean)
);

app.disable("x-powered-by");
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("X-Content-Type-Options", "nosniff");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: "10kb" }));

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL não configurada.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const allowedModules = new Set(["phishing", "awareness"]);

app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected", service: "security-lab-api" });
  } catch (error) {
    console.error("Health check database error:", error.message);
    res.status(503).json({ status: "error", database: "unavailable" });
  }
});

app.get("/api/progress", async (req, res) => {
  const studentId = String(req.query.studentId || "");
  if (!uuidPattern.test(studentId)) return res.status(400).json({ error: "studentId inválido" });
  try {
    const result = await pool.query(
      "SELECT completed_modules, updated_at FROM student_progress WHERE student_id = $1",
      [studentId]
    );
    const row = result.rows[0];
    res.json({ completedModules: row ? row.completed_modules : [], updatedAt: row ? row.updated_at : null });
  } catch (error) {
    console.error("Progress read error:", error.message);
    res.status(500).json({ error: "Não foi possível carregar o progresso." });
  }
});

app.put("/api/progress", async (req, res) => {
  const studentId = String(req.body.studentId || "");
  const modules = req.body.completedModules;
  if (!uuidPattern.test(studentId) || !Array.isArray(modules) || modules.length > allowedModules.size ||
      modules.some((item) => typeof item !== "string" || !allowedModules.has(item))) {
    return res.status(400).json({ error: "Dados de progresso inválidos." });
  }
  try {
    const result = await pool.query(
      `INSERT INTO student_progress (student_id, completed_modules, updated_at)
       VALUES ($1, $2::text[], NOW())
       ON CONFLICT (student_id) DO UPDATE
       SET completed_modules = EXCLUDED.completed_modules, updated_at = NOW()
       RETURNING completed_modules, updated_at`,
      [studentId, [...new Set(modules)]]
    );
    res.json({ completedModules: result.rows[0].completed_modules, updatedAt: result.rows[0].updated_at });
  } catch (error) {
    console.error("Progress write error:", error.message);
    res.status(500).json({ error: "Não foi possível salvar o progresso." });
  }
});

app.listen(port, "0.0.0.0", () => console.log(`Security Lab API listening on ${port}`));

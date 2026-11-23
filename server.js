const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const dns = require("dns").promises;

const app = express();
const port = Number(process.env.PORT || 3000);
const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || "https://segurity-lab.netlify.app")
    .split(",").map((origin) => origin.trim()).filter(Boolean)
);
const frontendUrl = (process.env.FRONTEND_URL || "https://segurity-lab.netlify.app").replace(/\/$/, "");
const allowedEmail = String(process.env.AUTH_EMAIL || "").trim().toLowerCase();
const allowedPhone = String(process.env.AUTH_PHONE_E164 || "").replace(/\D/g, "");

app.disable("x-powered-by");
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: "12kb" }));

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL não configurada.");
  process.exit(1);
}
if (!allowedEmail || !allowedPhone) {
  console.error("AUTH_EMAIL e AUTH_PHONE_E164 precisam estar configurados.");
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
const attempts = new Map();

function rateLimit(key, max = 8, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || entry.until <= now) {
    attempts.set(key, { count: 1, until: now + windowMs });
    return false;
  }
  entry.count += 1;
  return entry.count > max;
}
function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
function makeToken() {
  return crypto.randomBytes(32).toString("base64url");
}
function passwordHash(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (error, key) => {
      if (error) return reject(error);
      resolve("scrypt$16384$8$1$" + salt.toString("base64url") + "$" + key.toString("base64url"));
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const parts = String(stored || "").split("$");
    if (parts.length !== 6 || parts[0] !== "scrypt") return resolve(false);
    const salt = Buffer.from(parts[4], "base64url");
    const expected = Buffer.from(parts[5], "base64url");
    crypto.scrypt(password, salt, expected.length, { N: Number(parts[1]), r: Number(parts[2]), p: Number(parts[3]) }, (error, key) => {
      if (error) return reject(error);
      resolve(expected.length === key.length && crypto.timingSafeEqual(expected, key));
    });
  });
}
function getBearer(req) {
  const header = String(req.headers.authorization || "");
  return header.startsWith("Bearer ") ? header.slice(7).trim() : "";
}
async function requireAuth(req, res, next) {
  const token = getBearer(req);
  if (!token || token.length < 32) return res.status(401).json({ error: "Faça login para continuar." });
  try {
    const result = await pool.query(
      `SELECT u.id, u.email
       FROM security_lab_sessions s
       JOIN security_lab_users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW() AND s.revoked_at IS NULL
         AND (u.email_verified_at IS NOT NULL OR u.phone_verified_at IS NOT NULL)
       LIMIT 1`,
      [hash(token)]
    );
    if (!result.rowCount) return res.status(401).json({ error: "Sessão expirada. Entre novamente." });
    req.auth = result.rows[0];
    next();
  } catch (error) {
    console.error("Auth middleware error:", error.message);
    res.status(500).json({ error: "Não foi possível validar a sessão." });
  }
}

app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected", service: "security-lab-api", authConfigured: Boolean(allowedEmail && allowedPhone) });
  } catch (error) {
    console.error("Health check database error:", error.message);
    res.status(503).json({ status: "error", database: "unavailable" });
  }
});

// One authorized account: credentials are chosen on the first request and stored only as a scrypt hash.
app.post("/api/auth/request-verification", async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  if (rateLimit("request:" + ip, 4)) return res.status(429).json({ error: "Muitas tentativas. Aguarde alguns minutos." });
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!allowedEmail || !allowedPhone) return res.status(503).json({ error: "Os canais de autorização ainda não foram configurados no servidor." });
  if (email !== allowedEmail) return res.status(403).json({ error: "Este e-mail não está autorizado para este laboratório." });
  if (password.length < 10 || password.length > 128) return res.status(400).json({ error: "A senha deve ter entre 10 e 128 caracteres." });

  let client;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    const existing = await client.query(
      "SELECT id, password_hash, email_verified_at, phone_verified_at FROM security_lab_users WHERE email = $1 FOR UPDATE",
      [email]
    );
    let userId;
    if (existing.rowCount) {
      const user = existing.rows[0];
      if (user.email_verified_at || user.phone_verified_at) {
        await client.query("ROLLBACK");
        return res.status(409).json({ error: "Esta conta já foi autorizada. Entre com sua senha." });
      }
      if (!(await verifyPassword(password, user.password_hash))) {
        await client.query("ROLLBACK");
        return res.status(401).json({ error: "A senha não corresponde à conta criada anteriormente." });
      }
      userId = user.id;
      await client.query(
        "UPDATE security_lab_verification_batches SET expires_at = NOW(), completed_at = NOW() WHERE user_id = $1 AND completed_at IS NULL",
        [userId]
      );
    } else {
      const encodedPassword = await passwordHash(password);
      const inserted = await client.query(
        "INSERT INTO security_lab_users (email, phone_e164, password_hash) VALUES ($1, $2, $3) RETURNING id",
        [email, "+" + allowedPhone, encodedPassword]
      );
      userId = inserted.rows[0].id;
    }
    const batch = await client.query(
      "INSERT INTO security_lab_verification_batches (user_id, expires_at) VALUES ($1, NOW() + INTERVAL '30 minutes') RETURNING id",
      [userId]
    );
    const batchId = batch.rows[0].id;
    const emailToken = makeToken();
    const whatsappToken = makeToken();
    await client.query(
      "INSERT INTO security_lab_verification_tokens (batch_id, channel, token_hash, expires_at) VALUES ($1,'email',$2,NOW()+INTERVAL '30 minutes'),($1,'whatsapp',$3,NOW()+INTERVAL '30 minutes')",
      [batchId, hash(emailToken), hash(whatsappToken)]
    );
    await client.query("COMMIT");

    const emailLink = frontendUrl + "/confirm.html?token=" + encodeURIComponent(emailToken);
    const whatsappLink = frontendUrl + "/confirm.html?token=" + encodeURIComponent(whatsappToken);
    const subject = "Autorização de acesso - Security Lab";
    const emailBody = "Use este link individual para confirmar seu acesso ao Security Lab. O primeiro canal confirmado libera o acesso e invalida o outro: " + emailLink;
    const whatsappText = "Autorização de acesso ao Security Lab. Confirme por este link individual: " + whatsappLink + " (válido por 30 minutos).";
    res.status(201).json({
      message: "Links criados. Abra os aplicativos e toque em Enviar nas mensagens preparadas.",
      whatsappUrl: "https://wa.me/" + allowedPhone + "?text=" + encodeURIComponent(whatsappText),
      emailUrl: "mailto:" + encodeURIComponent(email) + "?subject=" + encodeURIComponent(subject) + "&body=" + encodeURIComponent(emailBody),
      expiresInMinutes: 30
    });
  } catch (error) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("Verification request error:", error.message);
    res.status(500).json({ error: "Não foi possível gerar os links de autorização." });
  } finally {
    if (client) client.release();
  }
});

app.post("/api/auth/confirm", async (req, res) => {
  const token = String(req.body.token || "");
  if (token.length < 32 || token.length > 128) return res.status(400).json({ error: "Link de confirmação inválido." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query(
      `SELECT t.id AS token_id, t.channel, t.batch_id, b.user_id, b.completed_at, b.expires_at AS batch_expires
       FROM security_lab_verification_tokens t
       JOIN security_lab_verification_batches b ON b.id = t.batch_id
       WHERE t.token_hash = $1
       FOR UPDATE OF t, b`,
      [hash(token)]
    );
    if (!found.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Link inválido ou já utilizado." });
    }
    const item = found.rows[0];
    if (item.completed_at || new Date(item.batch_expires) <= new Date()) {
      await client.query("ROLLBACK");
      return res.status(410).json({ error: "Este link expirou ou já foi confirmado por outro canal." });
    }
    await client.query(
      "UPDATE security_lab_verification_batches SET completed_at = NOW(), completed_channel = $2 WHERE id = $1",
      [item.batch_id, item.channel]
    );
    await client.query(
      "UPDATE security_lab_verification_tokens SET consumed_at = CASE WHEN id = $2 THEN NOW() ELSE consumed_at END, invalidated_at = CASE WHEN id <> $2 THEN NOW() ELSE invalidated_at END WHERE batch_id = $1",
      [item.batch_id, item.token_id]
    );
    const column = item.channel === "email" ? "email_verified_at" : "phone_verified_at";
    await client.query("UPDATE security_lab_users SET " + column + " = NOW(), updated_at = NOW() WHERE id = $1", [item.user_id]);
    await client.query("COMMIT");
    res.json({ success: true, message: "Autorização confirmada. Agora você já pode entrar no Security Lab." });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Confirmation error:", error.message);
    res.status(500).json({ error: "Não foi possível confirmar este link." });
  } finally {
    client.release();
  }
});

app.post("/api/auth/login", async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  if (rateLimit("login:" + ip, 8)) return res.status(429).json({ error: "Muitas tentativas. Aguarde alguns minutos." });
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  try {
    const result = await pool.query(
      "SELECT id, email, password_hash, email_verified_at, phone_verified_at FROM security_lab_users WHERE email = $1 LIMIT 1",
      [email]
    );
    const user = result.rows[0];
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({ error: "E-mail ou senha incorretos." });
    }
    if (!user.email_verified_at && !user.phone_verified_at) {
      return res.status(403).json({ error: "Confirme primeiro pelo link enviado por um dos canais." });
    }
    const sessionToken = makeToken();
    await pool.query(
      "INSERT INTO security_lab_sessions (user_id, token_hash, expires_at) VALUES ($1,$2,NOW()+INTERVAL '7 days')",
      [user.id, hash(sessionToken)]
    );
    res.json({ token: sessionToken, user: { email: user.email }, expiresInDays: 7 });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: "Não foi possível entrar." });
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => res.json({ user: { email: req.auth.email } }));
app.post("/api/auth/logout", requireAuth, async (req, res) => {
  try {
    await pool.query("UPDATE security_lab_sessions SET revoked_at = NOW() WHERE token_hash = $1", [hash(getBearer(req))]);
    res.json({ success: true });
  } catch (error) {
    console.error("Logout error:", error.message);
    res.status(500).json({ error: "Não foi possível encerrar a sessão." });
  }
});

app.get("/api/progress", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT completed_modules, updated_at FROM student_progress WHERE student_id = $1",
      [req.auth.id]
    );
    const row = result.rows[0];
    res.json({ completedModules: row ? row.completed_modules : [], updatedAt: row ? row.updated_at : null });
  } catch (error) {
    console.error("Progress read error:", error.message);
    res.status(500).json({ error: "Não foi possível carregar o progresso." });
  }
});

app.put("/api/progress", requireAuth, async (req, res) => {
  const modules = req.body.completedModules;
  if (!Array.isArray(modules) || modules.length > allowedModules.size ||
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
      [req.auth.id, [...new Set(modules)]]
    );
    res.json({ completedModules: result.rows[0].completed_modules, updatedAt: result.rows[0].updated_at });
  } catch (error) {
    console.error("Progress write error:", error.message);
    res.status(500).json({ error: "Não foi possível salvar o progresso." });
  }
});


function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
    (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || p[0] >= 224;
}
function isPublicAddress(address) {
  if (address.includes(":")) {
    const value = address.toLowerCase();
    return !(value === "::1" || value === "::" || value.startsWith("fc") ||
      value.startsWith("fd") || value.startsWith("fe80:") || value.startsWith("::ffff:127.") ||
      value.startsWith("::ffff:10.") || value.startsWith("::ffff:192.168."));
  }
  return !isPrivateIPv4(address);
}
app.post("/api/tools/domain-check", requireAuth, async (req, res) => {
  const raw = String(req.body.domain || "").trim().toLowerCase();
  const host = raw.replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/:\d+$/, "");
  if (!host || host.length > 253 || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host) ||
      host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) {
    return res.status(400).json({ error: "Informe um domínio público válido, sem caminho ou endereço local." });
  }
  try {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    const addresses = [...new Set(records.map(record => record.address))];
    const privateAnswers = addresses.filter(address => !isPublicAddress(address));
    res.json({
      domain: host,
      resolved: addresses.length > 0,
      addresses,
      warnings: privateAnswers.length ? ["O DNS retornou endereço privado ou reservado; não use esse domínio como destino público."] : [],
      checkedAt: new Date().toISOString(),
      note: "Consulta DNS somente. O servidor não abriu o site, não seguiu redirecionamentos e não enviou formulários."
    });
  } catch (error) {
    res.status(404).json({ domain: host, resolved: false, addresses: [], warnings: ["O domínio não resolveu no DNS ou não possui registro acessível."], checkedAt: new Date().toISOString() });
  }
});
app.post("/api/reports", requireAuth, async (req, res) => {
  const title = String(req.body.title || "").trim().slice(0, 120);
  const kind = String(req.body.kind || "security-check").slice(0, 40);
  const details = req.body.details && typeof req.body.details === "object" ? req.body.details : {};
  if (!title) return res.status(400).json({ error: "Informe um título para o relatório." });
  try {
    const result = await pool.query(
      "INSERT INTO security_lab_reports (user_id, kind, title, details) VALUES ($1,$2,$3,$4::jsonb) RETURNING id, kind, title, details, created_at",
      [req.auth.id, kind, title, JSON.stringify(details)]
    );
    res.status(201).json({ report: result.rows[0] });
  } catch (error) {
    console.error("Report save error:", error.message);
    res.status(500).json({ error: "Não foi possível salvar o relatório. Verifique se a migração de relatórios foi aplicada." });
  }
});
app.get("/api/reports", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, kind, title, details, created_at FROM security_lab_reports WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50",
      [req.auth.id]
    );
    res.json({ reports: result.rows });
  } catch (error) {
    console.error("Report list error:", error.message);
    res.status(500).json({ error: "Não foi possível carregar relatórios." });
  }
});

pool.query(`
  CREATE TABLE IF NOT EXISTS security_lab_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES security_lab_users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS security_lab_reports_user_created_idx
    ON security_lab_reports(user_id, created_at DESC);
`).then(() => {
  app.listen(port, "0.0.0.0", () => console.log("Security Lab API listening on " + port));
}).catch(error => {
  console.error("Security Lab reports schema initialization failed:", error.message);
  process.exit(1);
});

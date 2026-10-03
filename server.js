require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const path = require("path");

const app = express();
const db = new Database("dropzone.db");

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_BEFORE_PRODUCTION";

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("tiny"));
app.use(express.static(path.join(__dirname, "public")));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

/* =========================
   DATABASE
========================= */
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  ff_uid TEXT DEFAULT '',
  ff_username TEXT DEFAULT '',
  role TEXT NOT NULL DEFAULT 'PLAYER',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tournaments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'SQUAD',
  entry_fee REAL NOT NULL DEFAULT 0,
  prize_pool REAL NOT NULL DEFAULT 0,
  total_slots INTEGER NOT NULL DEFAULT 48,
  event_at TEXT,
  status TEXT NOT NULL DEFAULT 'OPEN',
  banner TEXT DEFAULT '',
  description TEXT DEFAULT '',
  room_id TEXT DEFAULT '',
  room_password TEXT DEFAULT '',
  room_publish_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  tournament_id INTEGER NOT NULL,
  slot_no INTEGER,
  ff_username TEXT NOT NULL,
  ff_uid TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  payment_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
  payment_ref TEXT DEFAULT '',
  payment_order_id TEXT DEFAULT '',
  payment_amount REAL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, tournament_id)
);

CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tournament_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  kills INTEGER NOT NULL DEFAULT 0,
  placement INTEGER NOT NULL DEFAULT 0,
  extra_points REAL NOT NULL DEFAULT 0,
  note TEXT DEFAULT '',
  UNIQUE(tournament_id, user_id)
);

CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function getSetting(key, fallback = "") {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
  return row ? row.value : fallback;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO settings(key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, String(value));
}

const defaultSettings = {
  site_name: "DROPZONE",
  tagline: "Free Fire Tournament Platform",
  logo_url: "",
  app_icon_url: "",
  favicon_url: "",
  banner_url: "",
  background_url: "",
  theme_color: "",
  payment_enabled: "0",
  payment_mode: "MANUAL",
  payment_display_name: "",
  payment_upi: "",
  payment_qr_url: "",
  currency: "INR",
  kill_points: "1",
  placement_points: JSON.stringify({"1":10,"2":7,"3":5,"4":3,"5":2})
};

for (const [key, value] of Object.entries(defaultSettings)) {
  if (getSetting(key, null) === null) setSetting(key, value);
}

function safeJson(value, fallback) {
  try { return JSON.parse(value); } catch { return fallback; }
}

function paymentRequired() {
  return getSetting("payment_enabled") === "1";
}

function audit(userId, action, detail = "") {
  db.prepare(`
    INSERT INTO audit_logs(user_id, action, detail)
    VALUES (?, ?, ?)
  `).run(userId || null, action, detail);
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    ff_uid: user.ff_uid || "",
    ff_username: user.ff_username || "",
    role: user.role,
    created_at: user.created_at
  };
}

function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function setAuthCookie(res, token) {
  res.cookie("dz_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function auth(req, res, next) {
  try {
    const token = req.cookies.dz_token;
    if (!token) return res.status(401).json({ error: "Login required" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = db.prepare(`
      SELECT id, name, email, ff_uid, ff_username, role, created_at
      FROM users WHERE id = ?
    `).get(decoded.id);

    if (!user) return res.status(401).json({ error: "Invalid session" });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid session" });
  }
}

function admin(req, res, next) {
  auth(req, res, () => {
    if (req.user.role === "OWNER" || req.user.role === "ADMIN") return next();
    return res.status(403).json({ error: "Admin access required" });
  });
}

function owner(req, res, next) {
  auth(req, res, () => {
    if (req.user.role === "OWNER") return next();
    return res.status(403).json({ error: "Owner access required" });
  });
}

function int(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function isoOrNull(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function countBooked(tournamentId) {
  return db.prepare(`
    SELECT COUNT(*) AS count
    FROM registrations
    WHERE tournament_id = ? AND status NOT IN ('CANCELLED','REJECTED')
  `).get(tournamentId).count;
}

function nextSlot(tournamentId) {
  const rows = db.prepare(`
    SELECT slot_no FROM registrations
    WHERE tournament_id = ? AND slot_no IS NOT NULL
    ORDER BY slot_no
  `).all(tournamentId);
  const used = new Set(rows.map(r => Number(r.slot_no)));
  let n = 1;
  while (used.has(n)) n++;
  return n;
}

function tournamentRow(row) {
  if (!row) return null;
  const booked = countBooked(row.id);
  return {
    ...row,
    booked_slots: booked,
    remaining_slots: Math.max(0, Number(row.total_slots) - booked)
  };
}

function roomAllowed(reg, tournament) {
  if (!reg || !tournament) return false;
  if (reg.status !== "CONFIRMED") return false;
  if (paymentRequired() && reg.payment_status !== "PAID") return false;
  if (!tournament.room_id && !tournament.room_password) return false;

  if (tournament.room_publish_at) {
    const publish = new Date(tournament.room_publish_at).getTime();
    if (Number.isFinite(publish) && Date.now() < publish) return false;
  }
  return true;
}

/* =========================
   OWNER
========================= */  
function seedOwner() {
  const email = String(
    process.env.OWNER_EMAIL || "owner@example.com"
  ).trim().toLowerCase();

  const password = String(
    process.env.OWNER_PASSWORD || "ChangeMe123!"
  );

  if (!email || !password) {
    throw new Error("OWNER_EMAIL and OWNER_PASSWORD are required.");
  }

  const hash = bcrypt.hashSync(password, 12);

  let owner = db.prepare(`
    SELECT id, email, role
    FROM users
    WHERE role = 'OWNER'
    ORDER BY id ASC
    LIMIT 1
  `).get();

  if (!owner) {
    owner = db.prepare(`
      SELECT id, email, role
      FROM users
      WHERE lower(email) = ?
      LIMIT 1
    `).get(email);
  }

  if (owner) {
    db.prepare(`
      UPDATE users
      SET
        name = ?,
        email = ?,
        password_hash = ?,
        role = 'OWNER'
      WHERE id = ?
    `).run(
      "DROPZONE Owner",
      email,
      hash,
      owner.id
    );

    console.log("OWNER account synchronized:", email);
  } else {
    db.prepare(`
      INSERT INTO users(name, email, password_hash, role)
      VALUES (?, ?, ?, 'OWNER')
    `).run(
      "DROPZONE Owner",
      email,
      hash
    );

    console.log("OWNER account created:", email);
  }
}

seedOwner();
/* =========================
   PUBLIC CONFIG
========================= */
app.get("/api/config", (req, res) => {
  res.json({
    site_name: getSetting("site_name"),
    tagline: getSetting("tagline"),
    logo_url: getSetting("logo_url"),
    app_icon_url: getSetting("app_icon_url"),
    favicon_url: getSetting("favicon_url"),
    banner_url: getSetting("banner_url"),
    background_url: getSetting("background_url"),
    theme_color: getSetting("theme_color"),
    payment_enabled: paymentRequired(),
    payment_mode: getSetting("payment_mode"),
    payment_display_name: getSetting("payment_display_name"),
    payment_upi: getSetting("payment_upi"),
    payment_qr_url: getSetting("payment_qr_url"),
    currency: getSetting("currency"),
    kill_points: num(getSetting("kill_points", "1"), 1),
    placement_points: safeJson(getSetting("placement_points"), {})
  });
});

/* =========================
   AUTH
========================= */
app.post("/api/register", (req, res) => {
  const {
    name, email, password, confirmPassword,
    ff_username = "", ff_uid = ""
  } = req.body || {};

  const cleanName = String(name || "").trim();
  const cleanEmail = String(email || "").trim().toLowerCase();

  if (!cleanName || !cleanEmail || !password) {
    return res.status(400).json({ error: "Name, email and password are required" });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  try {
    const hash = bcrypt.hashSync(password, 12);
    const result = db.prepare(`
      INSERT INTO users(name,email,password_hash,ff_username,ff_uid)
      VALUES (?,?,?,?,?)
    `).run(cleanName, cleanEmail, hash, String(ff_username || ""), String(ff_uid || ""));

    const user = db.prepare(`
      SELECT id,name,email,ff_uid,ff_username,role,created_at
      FROM users WHERE id = ?
    `).get(result.lastInsertRowid);

    const token = createToken(user);
    setAuthCookie(res, token);
    audit(user.id, "REGISTER", "New player account");
    res.status(201).json({ ok: true, user: publicUser(user) });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(e);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", (req, res) => {
  const email = String(req.body?.email || req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = db.prepare(`
    SELECT id,name,email,password_hash,ff_uid,ff_username,role,created_at
    FROM users WHERE lower(email) = ?
  `).get(email);

if (!user) {
  return res.status(401).json({ error: "OWNER email database में नहीं मिला" });
}
let passwordMatches = bcrypt.compareSync(
  password,
  user.password_hash
);

const ownerEmail = String(
  process.env.OWNER_EMAIL || ""
).trim().toLowerCase();

const ownerPassword = String(
  process.env.OWNER_PASSWORD || ""
);

if (
  !passwordMatches &&
  user.role === "OWNER" &&
  email === ownerEmail &&
  ownerPassword &&
  password === ownerPassword
) {
  const newHash = bcrypt.hashSync(ownerPassword, 12);

  db.prepare(`
    UPDATE users
    SET password_hash = ?
    WHERE id = ?
  `).run(newHash, user.id);

  passwordMatches = true;
}

if (!passwordMatches) {
  return res.status(401).json({
    error: "Password database वाले password से match नहीं हो रहा"
  });
}

  const token = createToken(user);
  setAuthCookie(res, token);
  audit(user.id, "LOGIN", "Successful login");
  res.json({ ok: true, user: publicUser(user) });
});
// Login authentication fix
app.post("/api/logout", (req, res) => {
  res.clearCookie("dz_token");
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ ok: true, user: publicUser(req.user) });
});

/* =========================
   PLAYER PUBLIC DATA
========================= */
app.get("/api/tournaments", (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM tournaments
    ORDER BY
      CASE WHEN status = 'OPEN' THEN 0 ELSE 1 END,
      datetime(event_at) ASC,
      id DESC
  `).all().map(tournamentRow);
  res.json(rows);
});

app.get("/api/tournaments/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM tournaments WHERE id = ?").get(int(req.params.id));
  if (!row) return res.status(404).json({ error: "Tournament not found" });
  res.json(tournamentRow(row));
});

app.get("/api/announcements", (req, res) => {
  res.json(db.prepare(`
    SELECT id,title,body,active,created_at
    FROM announcements WHERE active = 1
    ORDER BY id DESC
  `).all());
});

app.get("/api/leaderboard", (req, res) => {
  const tournamentId = req.query.tournament_id || req.query.tournamentId;
  const killPoint = num(getSetting("kill_points", "1"), 1);
  const placement = safeJson(getSetting("placement_points"), {});

  const where = tournamentId ? "WHERE r.tournament_id = ?" : "";
  const args = tournamentId ? [int(tournamentId)] : [];

  const rows = db.prepare(`
    SELECT
      r.tournament_id,
      r.user_id,
      u.name,
      u.ff_username,
      u.ff_uid,
      r.kills,
      r.placement,
      r.extra_points,
      r.note
    FROM results r
    JOIN users u ON u.id = r.user_id
    ${where}
    ORDER BY r.tournament_id, r.placement ASC, r.kills DESC, r.id ASC
  `).all(...args);

  res.json(rows.map(x => ({
    ...x,
    kill_points: Number(x.kills) * killPoint,
    placement_points: num(placement[String(x.placement)], 0),
    total_points:
      Number(x.kills) * killPoint +
      num(placement[String(x.placement)], 0) +
      Number(x.extra_points || 0)
  })));
});

/* =========================
   PLAYER REGISTRATION / PAYMENT
========================= */
app.post("/api/tournaments/:id/register", auth, (req, res) => {
  const tournamentId = int(req.params.id);
  const tournament = db.prepare("SELECT * FROM tournaments WHERE id = ?").get(tournamentId);

  if (!tournament) return res.status(404).json({ error: "Tournament not found" });
  if (tournament.status !== "OPEN") {
    return res.status(400).json({ error: "Tournament is not open" });
  }

  const existing = db.prepare(`
    SELECT * FROM registrations
    WHERE user_id = ? AND tournament_id = ?
  `).get(req.user.id, tournamentId);

  if (existing && !["CANCELLED","REJECTED"].includes(existing.status)) {
    return res.status(409).json({ error: "You are already registered for this tournament", registration: existing });
  }

  const booked = countBooked(tournamentId);
  if (booked >= Number(tournament.total_slots)) {
    return res.status(400).json({ error: "All slots are full" });
  }

  const ffUsername = String(req.body?.ff_username || req.user.ff_username || "").trim();
  const ffUid = String(req.body?.ff_uid || req.user.ff_uid || "").trim();

  if (!ffUsername || !ffUid) {
    return res.status(400).json({ error: "Free Fire username and UID are required" });
  }

  const paymentNeeded = paymentRequired();
  const status = paymentNeeded ? "PENDING" : "CONFIRMED";
  const paymentStatus = paymentNeeded ? "PENDING" : "NOT_REQUIRED";
  const slot = nextSlot(tournamentId);

  try {
    let id;
    if (existing) {
      db.prepare(`
        UPDATE registrations
        SET slot_no=?, ff_username=?, ff_uid=?, status=?, payment_status=?,
            payment_ref='', payment_order_id='', payment_amount=?
        WHERE id=?
      `).run(slot, ffUsername, ffUid, status, paymentStatus, Number(tournament.entry_fee || 0), existing.id);
      id = existing.id;
    } else {
      const result = db.prepare(`
        INSERT INTO registrations(
          user_id,tournament_id,slot_no,ff_username,ff_uid,status,
          payment_status,payment_amount
        ) VALUES (?,?,?,?,?,?,?,?)
      `).run(
        req.user.id, tournamentId, slot, ffUsername, ffUid,
        status, paymentStatus, Number(tournament.entry_fee || 0)
      );
      id = result.lastInsertRowid;
    }

    audit(req.user.id, "TOURNAMENT_REGISTER", `Tournament ${tournamentId}, registration ${id}`);
    const registration = db.prepare(`
      SELECT r.*, t.name AS tournament_name, t.entry_fee
      FROM registrations r JOIN tournaments t ON t.id=r.tournament_id
      WHERE r.id=?
    `).get(id);

    res.status(201).json({
      ok: true,
      registration,
      payment_required: paymentNeeded
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Tournament registration failed" });
  }
});

/* Alias kept for the existing frontend fallback */
app.post("/api/register-tournament", auth, (req, res) => {
  const id = req.body?.tournament_id || req.body?.tournamentId;
  req.params.id = String(id || "");
  return app._router.handle(req, res, () => {}, "post", "/api/tournaments/:id/register");
});

app.post("/api/registrations/:id/payment", auth, (req, res) => {
  const id = int(req.params.id);
  const reg = db.prepare(`
    SELECT r.*, t.entry_fee
    FROM registrations r JOIN tournaments t ON t.id=r.tournament_id
    WHERE r.id=?
  `).get(id);

  if (!reg) return res.status(404).json({ error: "Registration not found" });
  if (reg.user_id !== req.user.id) return res.status(403).json({ error: "Not your registration" });
  if (!paymentRequired()) {
    return res.status(400).json({ error: "Payment is currently disabled" });
  }

  const ref = String(req.body?.payment_ref || req.body?.utr || req.body?.transaction_id || "").trim();
  if (!ref) return res.status(400).json({ error: "Payment reference/UTR is required" });

  db.prepare(`
    UPDATE registrations
    SET payment_ref=?, payment_status='PENDING', status='PENDING'
    WHERE id=?
  `).run(ref, id);

  audit(req.user.id, "PAYMENT_SUBMITTED", `Registration ${id}, ref ${ref}`);
  res.json({ ok: true, message: "Payment submitted for admin verification" });
});

app.get("/api/my-registrations", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT
      r.*, t.name AS tournament_name, t.mode, t.entry_fee, t.prize_pool,
      t.event_at, t.status AS tournament_status, t.banner, t.description,
      t.room_publish_at
    FROM registrations r
    JOIN tournaments t ON t.id = r.tournament_id
    WHERE r.user_id=?
    ORDER BY r.id DESC
  `).all(req.user.id);
  res.json(rows);
});

app.get("/api/my-rooms/:id", auth, (req, res) => {
  const tournamentId = int(req.params.id);
  const tournament = db.prepare("SELECT * FROM tournaments WHERE id=?").get(tournamentId);
  const reg = db.prepare(`
    SELECT * FROM registrations
    WHERE user_id=? AND tournament_id=?
  `).get(req.user.id, tournamentId);

  if (!tournament || !reg) return res.status(404).json({ error: "Room not available" });

  if (!roomAllowed(reg, tournament)) {
    return res.status(403).json({ error: "Room details are not published or you are not confirmed" });
  }

  res.json({
    tournament_id: tournament.id,
    room_id: tournament.room_id,
    room_password: tournament.room_password,
    published: true
  });
});

/* =========================
   ADMIN DASHBOARD
========================= */
app.get("/api/admin/dashboard", admin, (req, res) => {
  const players = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='PLAYER'").get().c;
  const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='ADMIN'").get().c;
  const tournaments = db.prepare("SELECT COUNT(*) AS c FROM tournaments").get().c;
  const registrations = db.prepare("SELECT COUNT(*) AS c FROM registrations").get().c;
  const confirmed = db.prepare("SELECT COUNT(*) AS c FROM registrations WHERE status='CONFIRMED'").get().c;
  const pending = db.prepare("SELECT COUNT(*) AS c FROM registrations WHERE status='PENDING'").get().c;
  const paid = db.prepare("SELECT COUNT(*) AS c FROM registrations WHERE payment_status='PAID'").get().c;
  const pendingPayments = db.prepare("SELECT COUNT(*) AS c FROM registrations WHERE payment_status='PENDING'").get().c;
  const collected = db.prepare(`
    SELECT COALESCE(SUM(payment_amount),0) AS total
    FROM registrations WHERE payment_status='PAID'
  `).get().total;

  res.json({
    players, admins, tournaments, registrations,
    confirmed, pending, paid, pending_payments: pendingPayments,
    total_collected: Number(collected || 0)
  });
});

/* =========================
   ADMIN SETTINGS
========================= */
app.get("/api/admin/settings", admin, (req, res) => {
  const keys = [
    "site_name","tagline","logo_url","app_icon_url","favicon_url",
    "banner_url","background_url","theme_color","payment_enabled",
    "payment_mode","payment_display_name","payment_upi","payment_qr_url",
    "currency","kill_points","placement_points"
  ];

  const out = {};
  for (const key of keys) {
    const value = getSetting(key, "");
    out[key] = key === "placement_points" ? safeJson(value, {}) : value;
  }
  out.payment_enabled = out.payment_enabled === "1";
  out.kill_points = num(out.kill_points, 1);
  res.json(out);
});

app.put("/api/admin/settings", admin, (req, res) => {
  const body = req.body || {};
  const allowed = [
    "site_name","tagline","logo_url","app_icon_url","favicon_url",
    "banner_url","background_url","theme_color","payment_mode",
    "payment_display_name","payment_upi","payment_qr_url","currency"
  ];

  for (const key of allowed) {
    if (body[key] !== undefined) setSetting(key, body[key]);
  }

  if (body.payment_enabled !== undefined) {
    setSetting("payment_enabled", body.payment_enabled ? "1" : "0");
  }

  if (body.kill_points !== undefined) {
    setSetting("kill_points", Math.max(0, num(body.kill_points, 1)));
  }

  if (body.placement_points !== undefined) {
    const pp = body.placement_points;
    if (typeof pp !== "object" || Array.isArray(pp)) {
      return res.status(400).json({ error: "placement_points must be an object" });
    }
    setSetting("placement_points", JSON.stringify(pp));
  }

  audit(req.user.id, "UPDATE_SETTINGS", "Website/payment/scoring settings changed");
  res.json({ ok: true });
});

/* =========================
   ADMIN TOURNAMENTS
========================= */
app.get("/api/admin/tournaments", admin, (req, res) => {
  res.json(db.prepare("SELECT * FROM tournaments ORDER BY id DESC").all().map(tournamentRow));
});

app.post("/api/admin/tournaments", admin, (req, res) => {
  const b = req.body || {};
  const name = String(b.name || "").trim();
  if (!name) return res.status(400).json({ error: "Tournament name is required" });

  const result = db.prepare(`
    INSERT INTO tournaments(
      name,mode,entry_fee,prize_pool,total_slots,event_at,status,
      banner,description,room_id,room_password,room_publish_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    name,
    String(b.mode || "SQUAD"),
    Math.max(0, num(b.entry_fee, 0)),
    Math.max(0, num(b.prize_pool, 0)),
    Math.max(1, int(b.total_slots, 48)),
    isoOrNull(b.event_at),
    String(b.status || "OPEN"),
    String(b.banner || ""),
    String(b.description || ""),
    String(b.room_id || ""),
    String(b.room_password || ""),
    isoOrNull(b.room_publish_at)
  );

  audit(req.user.id, "CREATE_TOURNAMENT", `Tournament ${result.lastInsertRowid}`);
  res.status(201).json({
    ok: true,
    tournament: tournamentRow(
      db.prepare("SELECT * FROM tournaments WHERE id=?").get(result.lastInsertRowid)
    )
  });
});

app.put("/api/admin/tournaments/:id", admin, (req, res) => {
  const id = int(req.params.id);
  const old = db.prepare("SELECT * FROM tournaments WHERE id=?").get(id);
  if (!old) return res.status(404).json({ error: "Tournament not found" });

  const b = req.body || {};
  const name = String(b.name ?? old.name).trim();
  if (!name) return res.status(400).json({ error: "Tournament name is required" });

  db.prepare(`
    UPDATE tournaments SET
      name=?, mode=?, entry_fee=?, prize_pool=?, total_slots=?,
      event_at=?, status=?, banner=?, description=?,
      room_id=?, room_password=?, room_publish_at=?
    WHERE id=?
  `).run(
    name,
    String(b.mode ?? old.mode),
    Math.max(0, num(b.entry_fee, old.entry_fee)),
    Math.max(0, num(b.prize_pool, old.prize_pool)),
    Math.max(1, int(b.total_slots, old.total_slots)),
    b.event_at !== undefined ? isoOrNull(b.event_at) : old.event_at,
    String(b.status ?? old.status),
    String(b.banner ?? old.banner ?? ""),
    String(b.description ?? old.description ?? ""),
    String(b.room_id ?? old.room_id ?? ""),
    String(b.room_password ?? old.room_password ?? ""),
    b.room_publish_at !== undefined ? isoOrNull(b.room_publish_at) : old.room_publish_at,
    id
  );

  audit(req.user.id, "UPDATE_TOURNAMENT", `Tournament ${id}`);
  res.json({ ok: true, tournament: tournamentRow(db.prepare("SELECT * FROM tournaments WHERE id=?").get(id)) });
});

app.delete("/api/admin/tournaments/:id", admin, (req, res) => {
  const id = int(req.params.id);
  const exists = db.prepare("SELECT id FROM tournaments WHERE id=?").get(id);
  if (!exists) return res.status(404).json({ error: "Tournament not found" });

  const tx = db.transaction(() => {
    db.prepare("DELETE FROM results WHERE tournament_id=?").run(id);
    db.prepare("DELETE FROM registrations WHERE tournament_id=?").run(id);
    db.prepare("DELETE FROM tournaments WHERE id=?").run(id);
  });
  tx();

  audit(req.user.id, "DELETE_TOURNAMENT", `Tournament ${id}`);
  res.json({ ok: true });
});
/* =========================
   ADMIN TOURNAMENT TEMPLATES
========================= */

function getTournamentTemplates() {
  return safeJson(
    getSetting("tournament_templates", "[]"),
    []
  );
}

function saveTournamentTemplates(list) {
  setSetting(
    "tournament_templates",
    JSON.stringify(list)
  );
}

app.get(
  "/api/admin/tournament-templates",
  admin,
  (req, res) => {
    res.json(getTournamentTemplates());
  }
);

app.post(
  "/api/admin/tournament-templates",
  admin,
  (req, res) => {

    const b = req.body || {};

    const name = String(
      b.name || ""
    ).trim();

    if (!name) {
      return res.status(400).json({
        error: "Template name is required"
      });
    }

    const mode = String(
      b.mode || "SQUAD"
    ).toUpperCase();

    if (!["SOLO", "DUO", "SQUAD"].includes(mode)) {
      return res.status(400).json({
        error: "Invalid template mode"
      });
    }

    const list =
      getTournamentTemplates();

    const template = {
      id: Date.now(),

      name,

      mode,

      entry_fee: Math.max(
        0,
        num(b.entry_fee, 0)
      ),

      prize_pool: Math.max(
        0,
        num(b.prize_pool, 0)
      ),

      total_slots: Math.max(
        1,
        int(b.total_slots, 48)
      ),

      status: String(
        b.status || "OPEN"
      ).toUpperCase(),

      banner: String(
        b.banner || ""
      ),

      description: String(
        b.description || ""
      )
    };

    list.unshift(template);

    saveTournamentTemplates(list);

    audit(
      req.user.id,
      "CREATE_TOURNAMENT_TEMPLATE",
      `Template ${template.id}`
    );

    res.status(201).json({
      ok: true,
      template
    });
  }
);

app.put(
  "/api/admin/tournament-templates/:id",
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const list =
      getTournamentTemplates();

    const index =
      list.findIndex(
        x => Number(x.id) === id
      );

    if (index === -1) {
      return res.status(404).json({
        error: "Template not found"
      });
    }

    const old = list[index];
    const b = req.body || {};

    const name = String(
      b.name ?? old.name
    ).trim();

    if (!name) {
      return res.status(400).json({
        error: "Template name is required"
      });
    }

    const mode = String(
      b.mode ?? old.mode
    ).toUpperCase();

    if (!["SOLO", "DUO", "SQUAD"].includes(mode)) {
      return res.status(400).json({
        error: "Invalid template mode"
      });
    }

    list[index] = {
      ...old,

      name,

      mode,

      entry_fee: Math.max(
        0,
        num(
          b.entry_fee,
          old.entry_fee
        )
      ),

      prize_pool: Math.max(
        0,
        num(
          b.prize_pool,
          old.prize_pool
        )
      ),

      total_slots: Math.max(
        1,
        int(
          b.total_slots,
          old.total_slots
        )
      ),

      status: String(
        b.status ?? old.status
      ).toUpperCase(),

      banner: String(
        b.banner ??
        old.banner ??
        ""
      ),

      description: String(
        b.description ??
        old.description ??
        ""
      )
    };

    saveTournamentTemplates(list);

    audit(
      req.user.id,
      "UPDATE_TOURNAMENT_TEMPLATE",
      `Template ${id}`
    );

    res.json({
      ok: true,
      template: list[index]
    });
  }
);

app.delete(
  "/api/admin/tournament-templates/:id",
  admin,
  (req, res) => {

    const id =
      Number(req.params.id);

    const list =
      getTournamentTemplates();

    const next =
      list.filter(
        x => Number(x.id) !== id
      );

    if (next.length === list.length) {
      return res.status(404).json({
        error: "Template not found"
      });
    }

    saveTournamentTemplates(next);

    audit(
      req.user.id,
      "DELETE_TOURNAMENT_TEMPLATE",
      `Template ${id}`
    );

    res.json({
      ok: true
    });
  }
);
/* =========================
   ADMIN SLOT MANAGEMENT
========================= */

app.get("/api/admin/slots", admin, (req, res) => {
  const tournamentId = int(
    req.query.tournament_id || req.query.tournamentId
  );

  if (!tournamentId) {
    return res.status(400).json({
      error: "Tournament ID is required"
    });
  }

  const tournament = db.prepare(`
    SELECT id,name,total_slots,status,event_at
    FROM tournaments
    WHERE id=?
  `).get(tournamentId);

  if (!tournament) {
    return res.status(404).json({
      error: "Tournament not found"
    });
  }

  const registrations = db.prepare(`
    SELECT
      r.id,
      r.slot_no,
      r.ff_username,
      r.ff_uid,
      r.status,
      r.payment_status,
      r.payment_ref,
      r.payment_amount,
      r.created_at,
      u.name AS player_name,
      u.email AS player_email
    FROM registrations r
    JOIN users u ON u.id=r.user_id
    WHERE r.tournament_id=?
      AND r.status NOT IN ('CANCELLED','REJECTED')
    ORDER BY r.slot_no ASC, r.id ASC
  `).all(tournamentId);

  const occupied = new Map();

  registrations.forEach(row => {
    if (row.slot_no) {
      occupied.set(Number(row.slot_no), row);
    }
  });

  const slots = [];

  for (
    let slot = 1;
    slot <= Number(tournament.total_slots);
    slot++
  ) {
    const registration = occupied.get(slot);

    slots.push({
      slot_no: slot,
      occupied: !!registration,
      registration: registration || null
    });
  }

  res.json({
    tournament,
    total_slots: Number(tournament.total_slots),
    booked_slots: registrations.length,
    available_slots:
      Number(tournament.total_slots) - registrations.length,
    slots
  });
});


app.put("/api/admin/registrations/:id/slot", admin, (req, res) => {

  const registrationId = int(req.params.id);

  const registration = db.prepare(`
    SELECT *
    FROM registrations
    WHERE id=?
  `).get(registrationId);

  if (!registration) {
    return res.status(404).json({
      error: "Registration not found"
    });
  }

  const requestedSlot = int(
    req.body?.slot_no
  );

  if (!requestedSlot || requestedSlot < 1) {
    return res.status(400).json({
      error: "Invalid slot number"
    });
  }

  const tournament = db.prepare(`
    SELECT *
    FROM tournaments
    WHERE id=?
  `).get(registration.tournament_id);

  if (!tournament) {
    return res.status(404).json({
      error: "Tournament not found"
    });
  }

  if (requestedSlot > Number(tournament.total_slots)) {
    return res.status(400).json({
      error: "Slot exceeds tournament capacity"
    });
  }

  const occupied = db.prepare(`
    SELECT id,slot_no
    FROM registrations
    WHERE tournament_id=?
      AND slot_no=?
      AND id<>?
      AND status NOT IN ('CANCELLED','REJECTED')
    LIMIT 1
  `).get(
    registration.tournament_id,
    requestedSlot,
    registrationId
  );

  if (occupied) {
    return res.status(409).json({
      error: "This slot is already occupied"
    });
  }

  db.prepare(`
    UPDATE registrations
    SET slot_no=?
    WHERE id=?
  `).run(
    requestedSlot,
    registrationId
  );

  audit(
    req.user.id,
    "CHANGE_SLOT",
    `Registration ${registrationId}: slot ${requestedSlot}`
  );

  res.json({
    ok: true,
    slot_no: requestedSlot
  });
});


app.delete("/api/admin/registrations/:id/slot", admin, (req, res) => {

  const registrationId = int(req.params.id);

  const registration = db.prepare(`
    SELECT id,slot_no
    FROM registrations
    WHERE id=?
  `).get(registrationId);

  if (!registration) {
    return res.status(404).json({
      error: "Registration not found"
    });
  }

  db.prepare(`
    UPDATE registrations
    SET slot_no=NULL
    WHERE id=?
  `).run(registrationId);

  audit(
    req.user.id,
    "RELEASE_SLOT",
    `Registration ${registrationId}`
  );

  res.json({
    ok: true
  });
});
/* =========================
   ADMIN REGISTRATIONS / PAYMENTS
========================= */
app.get("/api/admin/registrations", admin, (req, res) => {
  const rows = db.prepare(`
    SELECT
      r.*, u.name AS player_name, u.email AS player_email,
      t.name AS tournament_name, t.entry_fee, t.event_at
    FROM registrations r
    JOIN users u ON u.id=r.user_id
    JOIN tournaments t ON t.id=r.tournament_id
    ORDER BY r.id DESC
  `).all();
  res.json(rows);
});

app.put("/api/admin/registrations/:id", admin, (req, res) => {
  const id = int(req.params.id);
  const reg = db.prepare("SELECT * FROM registrations WHERE id=?").get(id);
  if (!reg) return res.status(404).json({ error: "Registration not found" });

  const b = req.body || {};
  const status = b.status ? String(b.status).toUpperCase() : reg.status;
  const paymentStatus = b.payment_status ? String(b.payment_status).toUpperCase() : reg.payment_status;
  const allowedStatus = ["PENDING","CONFIRMED","CANCELLED","REJECTED"];
  const allowedPayment = ["NOT_REQUIRED","PENDING","PAID","FAILED","REFUNDED"];

  if (!allowedStatus.includes(status)) return res.status(400).json({ error: "Invalid registration status" });
  if (!allowedPayment.includes(paymentStatus)) return res.status(400).json({ error: "Invalid payment status" });

  const finalStatus = paymentStatus === "PAID" || paymentStatus === "NOT_REQUIRED"
    ? (status === "REJECTED" || status === "CANCELLED" ? status : "CONFIRMED")
    : status;

  db.prepare(`
    UPDATE registrations
    SET status=?, payment_status=?, payment_ref=?, payment_order_id=?, payment_amount=?
    WHERE id=?
  `).run(
    finalStatus,
    paymentStatus,
    String(b.payment_ref ?? reg.payment_ref ?? ""),
    String(b.payment_order_id ?? reg.payment_order_id ?? ""),
    num(b.payment_amount, reg.payment_amount || 0),
    id
  );

  audit(req.user.id, "UPDATE_REGISTRATION", `Registration ${id}: ${finalStatus}/${paymentStatus}`);
  res.json({ ok: true });
});

/* Convenience endpoint for payment verification */
app.post("/api/admin/registrations/:id/payment", admin, (req, res) => {
  const id = int(req.params.id);
  const reg = db.prepare("SELECT * FROM registrations WHERE id=?").get(id);
  if (!reg) return res.status(404).json({ error: "Registration not found" });

  const status = String(req.body?.payment_status || "").toUpperCase();
  if (!["PENDING","PAID","FAILED","REFUNDED","NOT_REQUIRED"].includes(status)) {
    return res.status(400).json({ error: "Invalid payment status" });
  }

  const registrationStatus =
    status === "PAID" || status === "NOT_REQUIRED" ? "CONFIRMED" :
    status === "REFUNDED" || status === "FAILED" ? "REJECTED" : "PENDING";

  db.prepare(`
    UPDATE registrations
    SET payment_status=?, status=?, payment_ref=?, payment_order_id=?, payment_amount=?
    WHERE id=?
  `).run(
    status,
    registrationStatus,
    String(req.body?.payment_ref ?? reg.payment_ref ?? ""),
    String(req.body?.payment_order_id ?? reg.payment_order_id ?? ""),
    num(req.body?.payment_amount, reg.payment_amount || 0),
    id
  );

  audit(req.user.id, "VERIFY_PAYMENT", `Registration ${id}: ${status}`);
  res.json({ ok: true });
});

/* =========================
   ADMIN PLAYERS / ROLES
========================= */
app.get("/api/admin/users", admin, (req, res) => {
  const rows = db.prepare(`
    SELECT id,name,email,ff_uid,ff_username,role,created_at
    FROM users ORDER BY id DESC
  `).all();
  res.json(rows);
});

app.put("/api/admin/users/:id/role", owner, (req, res) => {
  const id = int(req.params.id);
  const target = db.prepare("SELECT id,name,email,role FROM users WHERE id=?").get(id);
  if (!target) return res.status(404).json({ error: "User not found" });
  if (target.role === "OWNER") return res.status(400).json({ error: "Owner role cannot be changed" });

  const role = String(req.body?.role || "").toUpperCase();
  if (!["PLAYER","ADMIN"].includes(role)) {
    return res.status(400).json({ error: "Role must be PLAYER or ADMIN" });
  }

  db.prepare("UPDATE users SET role=? WHERE id=?").run(role, id);
  audit(req.user.id, "CHANGE_ROLE", `User ${id} -> ${role}`);
  res.json({ ok: true });
});

app.put("/api/admin/users/:id", admin, (req, res) => {
  const id = int(req.params.id);
  const target = db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if (!target) return res.status(404).json({ error: "User not found" });

  if (target.role === "OWNER" && req.user.role !== "OWNER") {
    return res.status(403).json({ error: "Only owner can edit owner account" });
  }

  const name = String(req.body?.name ?? target.name).trim();
  const ffUsername = String(req.body?.ff_username ?? target.ff_username ?? "");
  const ffUid = String(req.body?.ff_uid ?? target.ff_uid ?? "");

  if (!name) return res.status(400).json({ error: "Name is required" });

  db.prepare(`
    UPDATE users SET name=?, ff_username=?, ff_uid=? WHERE id=?
  `).run(name, ffUsername, ffUid, id);

  audit(req.user.id, "UPDATE_USER", `User ${id}`);
  res.json({ ok: true });
});

/* =========================
   ADMIN ANNOUNCEMENTS
========================= */
app.get("/api/admin/announcements", admin, (req, res) => {
  res.json(db.prepare("SELECT * FROM announcements ORDER BY id DESC").all());
});

app.post("/api/admin/announcements", admin, (req, res) => {
  const title = String(req.body?.title || "").trim();
  const body = String(req.body?.body || "").trim();
  if (!title || !body) return res.status(400).json({ error: "Title and body are required" });

  const result = db.prepare(`
    INSERT INTO announcements(title,body,active) VALUES (?,?,?)
  `).run(title, body, req.body?.active === false ? 0 : 1);

  audit(req.user.id, "CREATE_ANNOUNCEMENT", `Announcement ${result.lastInsertRowid}`);
  res.status(201).json({ ok: true });
});

app.put("/api/admin/announcements/:id", admin, (req, res) => {
  const id = int(req.params.id);
  const old = db.prepare("SELECT * FROM announcements WHERE id=?").get(id);
  if (!old) return res.status(404).json({ error: "Announcement not found" });

  db.prepare(`
    UPDATE announcements SET title=?, body=?, active=? WHERE id=?
  `).run(
    String(req.body?.title ?? old.title),
    String(req.body?.body ?? old.body),
    req.body?.active === undefined ? old.active : (req.body.active ? 1 : 0),
    id
  );

  audit(req.user.id, "UPDATE_ANNOUNCEMENT", `Announcement ${id}`);
  res.json({ ok: true });
});

app.delete("/api/admin/announcements/:id", admin, (req, res) => {
  const id = int(req.params.id);
  db.prepare("DELETE FROM announcements WHERE id=?").run(id);
  audit(req.user.id, "DELETE_ANNOUNCEMENT", `Announcement ${id}`);
  res.json({ ok: true });
});

/* =========================
   ADMIN RESULTS / SCORING
========================= */
app.get("/api/admin/results", admin, (req, res) => {
  const tid = req.query.tournament_id || req.query.tournamentId;
  const rows = db.prepare(`
    SELECT
      r.*, u.name AS player_name, u.email AS player_email,
      u.ff_username, u.ff_uid, t.name AS tournament_name
    FROM results r
    JOIN users u ON u.id=r.user_id
    JOIN tournaments t ON t.id=r.tournament_id
    ${tid ? "WHERE r.tournament_id=?" : ""}
    ORDER BY r.tournament_id, r.placement ASC, r.kills DESC
  `).all(...(tid ? [int(tid)] : []));
  res.json(rows);
});

app.post("/api/admin/results", admin, (req, res) => {
  const tournamentId = int(req.body?.tournament_id || req.body?.tournamentId);
  const userId = int(req.body?.user_id || req.body?.userId);

  if (!tournamentId || !userId) {
    return res.status(400).json({ error: "Tournament and player are required" });
  }

  const tournament = db.prepare("SELECT id FROM tournaments WHERE id=?").get(tournamentId);
  const user = db.prepare("SELECT id FROM users WHERE id=?").get(userId);
  if (!tournament || !user) return res.status(404).json({ error: "Tournament or player not found" });

  db.prepare(`
    INSERT INTO results(tournament_id,user_id,kills,placement,extra_points,note)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(tournament_id,user_id) DO UPDATE SET
      kills=excluded.kills,
      placement=excluded.placement,
      extra_points=excluded.extra_points,
      note=excluded.note
  `).run(
    tournamentId,
    userId,
    Math.max(0, int(req.body?.kills, 0)),
    Math.max(0, int(req.body?.placement, 0)),
    num(req.body?.extra_points, 0),
    String(req.body?.note || "")
  );

  audit(req.user.id, "UPSERT_RESULT", `Tournament ${tournamentId}, user ${userId}`);
  res.json({ ok: true });
});

app.delete("/api/admin/results/:id", admin, (req, res) => {
  const id = int(req.params.id);
  db.prepare("DELETE FROM results WHERE id=?").run(id);
  audit(req.user.id, "DELETE_RESULT", `Result ${id}`);
  res.json({ ok: true });
});

app.get("/api/admin/scoring", admin, (req, res) => {
  res.json({
    kill_points: num(getSetting("kill_points", "1"), 1),
    placement_points: safeJson(getSetting("placement_points"), {})
  });
});

app.put("/api/admin/scoring", admin, (req, res) => {
  if (req.body?.kill_points !== undefined) {
    setSetting("kill_points", Math.max(0, num(req.body.kill_points, 1)));
  }
  if (req.body?.placement_points !== undefined) {
    if (typeof req.body.placement_points !== "object" || Array.isArray(req.body.placement_points)) {
      return res.status(400).json({ error: "placement_points must be an object" });
    }
    setSetting("placement_points", JSON.stringify(req.body.placement_points));
  }

  audit(req.user.id, "UPDATE_SCORING", "Scoring settings changed");
  res.json({ ok: true });
});

/* =========================
   AUDIT LOGS / HEALTH
========================= */
app.get("/api/admin/audit-logs", owner, (req, res) => {
  res.json(db.prepare(`
    SELECT a.*, u.name AS user_name, u.email AS user_email
    FROM audit_logs a
    LEFT JOIN users u ON u.id=a.user_id
    ORDER BY a.id DESC LIMIT 500
  `).all());
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, app: "DROPZONE", time: new Date().toISOString() });
});

/* =========================
   ERROR HANDLER
========================= */
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API route not found" });
  }
  next();
});

app.use((err, req, res, next) => {
  console.error(err);
  if (req.path.startsWith("/api/")) {
    return res.status(500).json({ error: "Server error" });
  }
  res.status(500).send("Server error");
});

app.listen(PORT, () => {
  console.log(`DROPZONE running on port ${PORT}`);
});

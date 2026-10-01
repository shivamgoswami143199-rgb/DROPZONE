require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const morgan = require("morgan");
const path = require("path");

const app = express();

const db = new Database("dropzone.db");

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_SECRET_BEFORE_PRODUCTION";

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("tiny"));

app.use(express.static(path.join(__dirname, "public")));


// =====================================================
// DATABASE
// =====================================================

db.pragma("journal_mode = WAL");

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


// =====================================================
// SETTINGS
// =====================================================

function getSetting(key, fallback = "") {
    const row = db
        .prepare("SELECT value FROM settings WHERE key = ?")
        .get(key);

    return row ? row.value : fallback;
}

function setSetting(key, value) {
    db.prepare(`
        INSERT INTO settings(key, value)
        VALUES (?, ?)
        ON CONFLICT(key)
        DO UPDATE SET value = excluded.value
    `).run(key, String(value));
}

const defaultSettings = {
    site_name: "DROPZONE",
    tagline: "Free Fire Tournament Platform",

    payment_enabled: "0",
    payment_mode: "MANUAL",

    payment_display_name: "",
    payment_upi: "",
    payment_qr_url: "",

    kill_points: "1",

    placement_points: JSON.stringify({
        "1": 10,
        "2": 7,
        "3": 5,
        "4": 3,
        "5": 2
    }),

    currency: "INR"
};

for (const [key, value] of Object.entries(defaultSettings)) {
    if (getSetting(key, null) === null) {
        setSetting(key, value);
    }
}


// =====================================================
// OWNER
// =====================================================

function seedOwner() {
    const email = (
        process.env.OWNER_EMAIL || "owner@example.com"
    ).toLowerCase();

    const password =
        process.env.OWNER_PASSWORD || "ChangeMe123!";

    const existing = db
        .prepare("SELECT id FROM users WHERE email = ?")
        .get(email);

    if (!existing) {
        const hash = bcrypt.hashSync(password, 12);

        db.prepare(`
            INSERT INTO users(
                name,
                email,
                password_hash,
                role
            )
            VALUES (?, ?, ?, 'OWNER')
        `).run(
            "DROPZONE Owner",
            email,
            hash
        );

        console.log("OWNER account created:");
        console.log("Email:", email);
        console.log("Password:", password);
    }
}

seedOwner();


// =====================================================
// HELPERS
// =====================================================

function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

function audit(userId, action, detail = "") {
    db.prepare(`
        INSERT INTO audit_logs(
            user_id,
            action,
            detail
        )
        VALUES (?, ?, ?)
    `).run(userId, action, detail);
}

function safeJson(value, fallback) {
    try {
        return JSON.parse(value);
    } catch {
        return fallback;
    }
}

function paymentRequired() {
    return getSetting("payment_enabled") === "1";
}


// =====================================================
// AUTH MIDDLEWARE
// =====================================================

function auth(req, res, next) {
    try {
        const token = req.cookies.dz_token;

        if (!token) {
            return res.status(401).json({
                error: "Login required"
            });
        }

        const decoded = jwt.verify(
            token,
            JWT_SECRET
        );

        const user = db.prepare(`
            SELECT
                id,
                name,
                email,
                ff_uid,
                ff_username,
                role,
                created_at
            FROM users
            WHERE id = ?
        `).get(decoded.id);

        if (!user) {
            return res.status(401).json({
                error: "Invalid session"
            });
        }

        req.user = user;

        next();

    } catch (error) {
        return res.status(401).json({
            error: "Invalid session"
        });
    }
}


function admin(req, res, next) {

    auth(req, res, () => {

        if (
            req.user.role === "OWNER" ||
            req.user.role === "ADMIN"
        ) {
            return next();
        }

        return res.status(403).json({
            error: "Admin access required"
        });
    });
}


function owner(req, res, next) {

    auth(req, res, () => {

        if (req.user.role === "OWNER") {
            return next();
        }

        return res.status(403).json({
            error: "Owner access required"
        });
    });
}


// =====================================================
// PUBLIC CONFIG
// =====================================================

app.get("/api/config", (req, res) => {

    res.json({

        site_name:
            getSetting("site_name"),

        tagline:
            getSetting("tagline"),

        payment_enabled:
            getSetting("payment_enabled") === "1",

        payment_mode:
            getSetting("payment_mode"),

        payment_display_name:
            getSetting("payment_display_name"),

        payment_upi:
            getSetting("payment_upi"),

        payment_qr_url:
            getSetting("payment_qr_url"),

        currency:
            getSetting("currency"),

        kill_points:
            Number(
                getSetting("kill_points", "1")
            ),

        placement_points:
            safeJson(
                getSetting("placement_points"),
                {}
            )
    });
});


// =====================================================
// REGISTER
// =====================================================

app.post("/api/register", (req, res) => {

    const {
        name,
        email,
        password,
        confirmPassword,
        ff_username = "",
        ff_uid = ""
    } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            error:
                "Name, email and password are required"
        });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({
            error: "Passwords do not match"
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            error:
                "Password must be at least 6 characters"
        });
    }

    try {

        const hash =
            bcrypt.hashSync(password, 12);

        const result = db.prepare(`
            INSERT INTO users(
                name,
                email,
                password_hash,
                ff_username,
                ff_uid
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            name,
            email.toLowerCase(),
            hash,
            ff_username,
            ff_uid
        );

        const user = db.prepare(`
            SELECT
                id,
                name,
                email,
                ff_uid,
                ff_username,
                role
            FROM users
            WHERE id = ?
        `).get(result.lastInsertRowid);

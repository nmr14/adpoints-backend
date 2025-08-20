
// Adpoints Backend Server v2
import express from "express";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const db = new Database(process.env.DB_PATH || "./adpoints.db");

// إنشاء الجداول
db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    points INTEGER DEFAULT 0
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS ads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    url TEXT,
    duration INTEGER,
    reward_points INTEGER
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ad_id INTEGER,
    timestamp INTEGER
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    reward TEXT,
    status TEXT DEFAULT 'pending'
)`).run();

// إنشاء حساب الأدمن إذا ما كان موجود
if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
    const exists = db.prepare("SELECT * FROM users WHERE username=?").get(process.env.ADMIN_USERNAME);
    if (!exists) {
        const hashed = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
        db.prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)")
          .run(process.env.ADMIN_USERNAME, hashed, "admin");
        console.log("✅ Admin account created");
    }
}

function generateToken(user) {
    return jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" });
}

function auth(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.sendStatus(401);
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

function adminOnly(req, res, next) {
    if (req.user.role !== "admin") return res.sendStatus(403);
    next();
}

// تسجيل مستخدم
app.post("/register", (req, res) => {
    const { username, password } = req.body;
    try {
        const hashed = bcrypt.hashSync(password, 10);
        const info = db.prepare("INSERT INTO users (username,password) VALUES (?,?)").run(username, hashed);
        res.json({ id: info.lastInsertRowid });
    } catch {
        res.status(400).json({ error: "Username already exists" });
    }
});

// تسجيل دخول
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: "Invalid credentials" });
    const token = generateToken(user);
    res.json({ token, role: user.role });
});

// الحصول على الإعلانات
app.get("/ads", auth, (req, res) => {
    const ads = db.prepare("SELECT * FROM ads").all();
    res.json(ads);
});

// مشاهدة إعلان
app.post("/ads/:id/view", auth, (req, res) => {
    const { id } = req.params;
    const now = Date.now();
    const cooldown = parseInt(process.env.COOLDOWN_MS || "30000");
    const lastView = db.prepare("SELECT * FROM views WHERE user_id=? ORDER BY timestamp DESC LIMIT 1").get(req.user.id);
    if (lastView && now - lastView.timestamp < cooldown) {
        return res.status(400).json({ error: "Cooldown active" });
    }
    db.prepare("INSERT INTO views (user_id,ad_id,timestamp) VALUES (?,?,?)").run(req.user.id, id, now);
    const ad = db.prepare("SELECT * FROM ads WHERE id=?").get(id);
    db.prepare("UPDATE users SET points=points+? WHERE id=?").run(ad.reward_points, req.user.id);
    res.json({ success: true, reward: ad.reward_points });
});

// طلب استبدال النقاط
app.post("/redeem", auth, (req, res) => {
    const { reward } = req.body;
    db.prepare("INSERT INTO redemptions (user_id,reward) VALUES (?,?)").run(req.user.id, reward);
    res.json({ success: true });
});

// 🔹 مسارات الأدمن
app.post("/admin/ads", auth, adminOnly, (req, res) => {
    const { title, url, duration, reward_points } = req.body;
    const info = db.prepare("INSERT INTO ads (title,url,duration,reward_points) VALUES (?,?,?,?)")
        .run(title, url, duration, reward_points);
    res.json({ id: info.lastInsertRowid });
});

app.get("/admin/redemptions", auth, adminOnly, (req, res) => {
    res.json(db.prepare("SELECT * FROM redemptions").all());
});

app.post("/admin/redemptions/:id/:action", auth, adminOnly, (req, res) => {
    const { id, action } = req.params;
    if (!["approve","reject"].includes(action)) return res.status(400).json({ error: "Invalid action" });
    db.prepare("UPDATE redemptions SET status=? WHERE id=?").run(action, id);
    res.json({ success: true });
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log("🚀 Server running on port " + port));

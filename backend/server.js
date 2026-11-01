require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

// Must match the client's PBKDF2 iteration count for new accounts
const KDF_ITERATIONS = 600000;

if (!MONGODB_URI || !JWT_SECRET) {
    console.error("MONGODB_URI and JWT_SECRET must be set in .env");
    process.exit(1);
}

let usersCollection;
let passwordsCollection;

const connectDB = async () => {
    try {
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        const db = client.db("secureKeep");
        usersCollection = db.collection("users");
        passwordsCollection = db.collection("passwords");
        await usersCollection.createIndex({ username: 1 }, { unique: true });
        await passwordsCollection.createIndex({ userId: 1 });
        console.log("Connected to MongoDB successfully");
    } catch (error) {
        console.error("MongoDB connection error:", error);
        process.exit(1);
    }
};

// Behind a reverse proxy (e.g. Render), trust its X-Forwarded-For so rate
// limiting sees each visitor's real IP. Set TRUST_PROXY=1 there.
if (process.env.TRUST_PROXY) {
    app.set("trust proxy", Number(process.env.TRUST_PROXY) || 1);
}

app.use(express.json({ limit: "100kb" }));

// Same-origin requests (Vite proxy in dev, or frontend served from this host)
// need no CORS. Only origins listed in ALLOWED_ORIGINS may call cross-origin.
app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
            callback(null, false);
        },
        methods: ["GET", "POST", "PUT", "DELETE"],
    })
);

// Slow down online guessing of master passwords: 10 attempts per IP per 15 min
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Too many attempts. Try again in 15 minutes." },
});
app.use("/api/auth/login", authLimiter);
app.use("/api/auth/register", authLimiter);

// ---------- helpers ----------

const USERNAME_RE = /^[a-zA-Z0-9_.@-]{3,64}$/;
const HEX_RE = (len) => new RegExp(`^[0-9a-f]{${len}}$`);
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

const normalizeUsername = (u) => (typeof u === "string" ? u.trim().toLowerCase() : "");

// The client sends an auth key derived from the master password (never the
// password or the encryption key). We store only a salted scrypt hash of it.
const hashAuthKey = (authKey, salt) =>
    crypto.scryptSync(authKey, salt, 64).toString("hex");

// Deterministic fake salt for unknown users so /prelogin doesn't reveal
// which usernames exist.
const fakeSalt = (username) =>
    crypto.createHmac("sha256", JWT_SECRET).update("salt:" + username).digest("hex").slice(0, 32);

const isValidEntry = ({ iv, data }) =>
    typeof iv === "string" && BASE64_RE.test(iv) && iv.length <= 24 &&
    typeof data === "string" && BASE64_RE.test(data) && data.length <= 50000;

const requireAuth = (req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.userId = new ObjectId(payload.sub);
        next();
    } catch {
        res.status(401).json({ error: "Invalid or expired session" });
    }
};

const parseId = (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
        res.status(400).json({ error: "Invalid id" });
        return null;
    }
    return new ObjectId(req.params.id);
};

// ---------- auth routes ----------

app.post("/api/auth/register", async (req, res) => {
    try {
        const username = normalizeUsername(req.body.username);
        const { salt, authKey } = req.body;
        if (!USERNAME_RE.test(username)) {
            return res.status(400).json({ error: "Username must be 3-64 characters (letters, numbers, _ . @ -)" });
        }
        if (typeof salt !== "string" || !HEX_RE(32).test(salt) ||
            typeof authKey !== "string" || !HEX_RE(64).test(authKey)) {
            return res.status(400).json({ error: "Invalid registration data" });
        }

        const serverSalt = crypto.randomBytes(16).toString("hex");
        const result = await usersCollection.insertOne({
            username,
            kdfSalt: salt,
            kdfIterations: KDF_ITERATIONS,
            authSalt: serverSalt,
            authHash: hashAuthKey(authKey, serverSalt),
            createdAt: new Date(),
        });

        const token = jwt.sign({ sub: result.insertedId.toString() }, JWT_SECRET, { expiresIn: "1h" });
        res.status(201).json({ token });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({ error: "Username already taken" });
        }
        console.error("Register error:", error);
        res.status(500).json({ error: "Registration failed" });
    }
});

// Returns the KDF parameters so the client can derive keys on any device.
app.post("/api/auth/prelogin", async (req, res) => {
    try {
        const username = normalizeUsername(req.body.username);
        const user = await usersCollection.findOne({ username });
        res.json({
            salt: user ? user.kdfSalt : fakeSalt(username),
            iterations: user ? user.kdfIterations : KDF_ITERATIONS,
        });
    } catch (error) {
        console.error("Prelogin error:", error);
        res.status(500).json({ error: "Login failed" });
    }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const username = normalizeUsername(req.body.username);
        const { authKey } = req.body;
        if (typeof authKey !== "string" || !HEX_RE(64).test(authKey)) {
            return res.status(400).json({ error: "Invalid login data" });
        }

        const user = await usersCollection.findOne({ username });
        const expected = Buffer.from(user ? user.authHash : "0".repeat(128), "hex");
        const actual = Buffer.from(hashAuthKey(authKey, user ? user.authSalt : "dummy"), "hex");
        if (!user || !crypto.timingSafeEqual(expected, actual)) {
            return res.status(401).json({ error: "Incorrect username or master password" });
        }

        const token = jwt.sign({ sub: user._id.toString() }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Login failed" });
    }
});

// ---------- vault routes (server only ever sees ciphertext) ----------

app.get("/api/passwords", requireAuth, async (req, res) => {
    try {
        const entries = await passwordsCollection
            .find({ userId: req.userId })
            .sort({ createdAt: 1 })
            .toArray();
        res.json(entries.map((e) => ({ _id: e._id.toString(), iv: e.iv, data: e.data })));
    } catch (error) {
        console.error("Fetch error:", error);
        res.status(500).json({ error: "Failed to fetch passwords" });
    }
});

app.post("/api/passwords", requireAuth, async (req, res) => {
    try {
        if (!isValidEntry(req.body)) {
            return res.status(400).json({ error: "Invalid encrypted entry" });
        }
        const now = new Date();
        const result = await passwordsCollection.insertOne({
            userId: req.userId,
            iv: req.body.iv,
            data: req.body.data,
            createdAt: now,
            updatedAt: now,
        });
        res.status(201).json({ success: true, id: result.insertedId.toString() });
    } catch (error) {
        console.error("Save error:", error);
        res.status(500).json({ error: "Failed to save password" });
    }
});

app.put("/api/passwords/:id", requireAuth, async (req, res) => {
    try {
        const id = parseId(req, res);
        if (!id) return;
        if (!isValidEntry(req.body)) {
            return res.status(400).json({ error: "Invalid encrypted entry" });
        }
        const result = await passwordsCollection.updateOne(
            { _id: id, userId: req.userId },
            { $set: { iv: req.body.iv, data: req.body.data, updatedAt: new Date() } }
        );
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Not found" });
        }
        res.json({ success: true });
    } catch (error) {
        console.error("Update error:", error);
        res.status(500).json({ error: "Failed to update password" });
    }
});

app.delete("/api/passwords/:id", requireAuth, async (req, res) => {
    try {
        const id = parseId(req, res);
        if (!id) return;
        const result = await passwordsCollection.deleteOne({ _id: id, userId: req.userId });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "Not found" });
        }
        res.json({ success: true });
    } catch (error) {
        console.error("Delete error:", error);
        res.status(500).json({ error: "Failed to delete password" });
    }
});

// In production, serve the built React app from this server so the frontend
// and API share one origin (run `npm run build` in client/ first).
const CLIENT_DIST = path.join(__dirname, "../client/dist");
if (fs.existsSync(CLIENT_DIST)) {
    app.use(express.static(CLIENT_DIST));
    app.get(/^(?!\/api\/).*/, (req, res) => res.sendFile(path.join(CLIENT_DIST, "index.html")));
}

connectDB().then(() => {
    app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
    });
});

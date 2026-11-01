# SecureKeep Documentation

SecureKeep is a zero-knowledge password manager. Users save website logins (site, username, password), and every entry is encrypted in the browser before it is sent anywhere. The server and the database only ever hold ciphertext, so nobody can read a saved password without the user's master password, not even someone with full access to the database.

This document explains how the frontend, backend and database work together.

---

## 1. Tech stack

| Layer | Technology | Role |
|---|---|---|
| Frontend | React 18, Vite, Tailwind CSS, react-toastify, Heroicons | User interface |
| Browser crypto | Web Crypto API (built into the browser) | Key derivation, encryption, decryption |
| Backend | Node.js, Express 4 | REST API |
| Backend libraries | jsonwebtoken, express-rate-limit, cors, dotenv, Node `crypto` | Sessions, rate limiting, CORS, config, hashing |
| Database | MongoDB Atlas, `mongodb` driver 5 | Stores users and encrypted entries |
| Dev tools | nodemon, ESLint | Auto-restart, linting |

---

## 2. Folder structure

```
SecureKeep/
├── client/                      Frontend (React + Vite)
│   ├── index.html
│   ├── vite.config.js           Dev proxy: /api → http://localhost:3000
│   ├── tailwind.config.js
│   └── src/
│       ├── main.jsx             Mounts <App /> into index.html
│       ├── App.jsx              Layout: Navbar + Manager + Footer
│       ├── vaultCrypto.js       All cryptography (PBKDF2, AES-GCM, salts)
│       └── Components/
│           ├── Navbar.jsx
│           ├── Manager.jsx      Login/sign-up screen, vault, all API calls
│           └── Footer.jsx
├── backend/                     Backend (Node + Express)
│   ├── server.js                Middleware, routes, MongoDB connection
│   ├── migrate-legacy.js        One-time v1 → v2 data migration script
│   └── .env                     Secrets and config (not committed)
├── README.md
├── DOCUMENTATION.md             This file
└── LICENSE                      MIT
```

---

## 3. The big picture

```
┌──────────────── BROWSER (trusted) ────────────────┐            ┌──────── BACKEND :3000 ────────┐        ┌──── MONGODB ATLAS ────┐
│                                                   │            │                               │        │                       │
│  React UI (Manager.jsx)                           │  authKey   │  Middleware                   │        │  users                │
│     │  master password, entries                   │  {iv,data} │   express.json (100 kB)       │        │   username (unique)   │
│     ▼                                             │  Bearer JWT│   CORS allowlist              │ driver │   kdfSalt             │
│  vaultCrypto.js (Web Crypto API)                  │ ─────────► │   rate limit (login/register) │ ◄────► │   kdfIterations       │
│     PBKDF2 → encKey + authKey                     │            │   requireAuth (JWT check)     │        │   authSalt, authHash  │
│     AES-256-GCM encrypt / decrypt                 │ ◄───────── │                               │        │                       │
│     │                                             │  salt, JWT │  Routes                       │        │  passwords            │
│     ▼                                             │  [{iv,data}]│   /api/auth/*                 │        │   userId (indexed)    │
│  Memory only: master password, encKey, JWT,       │            │   /api/passwords              │        │   iv, data            │
│               decrypted entries                   │            │                               │        │   createdAt/updatedAt │
└───────────────────────────────────────────────────┘            └───────────────────────────────┘        └───────────────────────┘
                     ▲
           TRUST BOUNDARY: the master password, encryption key and plain-text entries never cross it
```

The main rule of the design is that anything that could reveal a password stays in the browser. The server receives only two kinds of data:

- an **auth key** that proves the user knows the master password, but can't decrypt anything
- **ciphertext** (`{ iv, data }`) that it stores without being able to read

---

## 4. How the three parts connect

### Ports and the dev proxy

| Part | Address | Started with |
|---|---|---|
| Frontend (Vite dev server) | http://localhost:5173 | `cd client` then `npm run dev` |
| Backend (Express) | http://localhost:3000 | `cd backend` then `npm run dev` |
| Database | MongoDB Atlas (cloud) | Connection string in `backend/.env` |

The React code calls relative URLs such as `/api/auth/login`. In development, Vite's proxy (`client/vite.config.js`) forwards every `/api` request to `http://localhost:3000`. To the browser, the frontend and API look like one origin, so no CORS setup is needed.

There is also a single-server mode: run `npm run build` in `client/` to produce `client/dist`, then `npm start` in `backend/`. When `client/dist` exists, Express serves the built React app and the API together on port 3000.

### Backend startup order

1. `dotenv` loads `backend/.env`.
2. If `MONGODB_URI` or `JWT_SECRET` is missing, the server prints an error and exits.
3. `connectDB()` connects to MongoDB, selects the `secureKeep` database, and creates the indexes (unique `username`, and `userId`).
4. If the connection fails, the server exits. This is why the frontend shows "Could not reach the server" when Atlas is unreachable, for example when your IP isn't in Atlas **Network Access**.
5. Only after a successful connection does Express start listening on port 3000.

### Configuration (`backend/.env`)

| Variable | Required | Purpose |
|---|---|---|
| `MONGODB_URI` | Yes | MongoDB Atlas connection string |
| `JWT_SECRET` | Yes | Secret used to sign JWTs and fake salts |
| `PORT` | No | API port, default 3000 |
| `ALLOWED_ORIGINS` | No | Comma-separated origins allowed to call the API cross-origin |
| `TRUST_PROXY` | No | Set when running behind a reverse proxy, so rate limiting sees real IPs |

`ENCRYPTION_KEY` in the current `.env` is a leftover from v1. The current code doesn't read it.

---

## 5. Frontend

### Components

- **`App.jsx`** lays out the page: `Navbar`, then `Manager`, then `Footer`.
- **`Manager.jsx`** holds nearly all the app's logic: the sign-up and login screen, the vault table, the add/edit form, and every API call.
- **`vaultCrypto.js`** holds all the cryptography. It's plain JavaScript, separate from React.

### State in `Manager.jsx`

All of this is React state, which lives in browser memory (RAM). Nothing secret is written to disk.

| State | Holds |
|---|---|
| `username`, `masterPassword`, `confirmPassword` | Login and sign-up form fields |
| `encKey` | The AES-GCM `CryptoKey` (memory only) |
| `token` | The JWT (memory only) |
| `passwords` | The decrypted vault entries |
| `form` | The add/edit form (`_id` is set when editing) |
| `isUnlocked`, `isNewUser`, `isBusy` | Which screen to show, and loading state |
| `passwordStrength` | Master password strength score from 0 to 5 |

The only thing saved in `localStorage` is the last username (`securekeep:lastUsername`), so the login form can fill it in. Refreshing the page clears everything else, and the user logs in again.

### Helpers for API calls

- **`postJson(url, body)`** sends a JSON `POST` with no token. It's used for the three auth routes.
- **`authFetch(url, options)`** adds `Authorization: Bearer <token>` to the request. If the server answers **401**, it locks the vault automatically with "Session expired. Please unlock again."

### Features

- **Strength meter:** awards one point each for 8+ characters, 12+ characters, an uppercase letter, a lowercase letter, a digit and a symbol, capped at 5. Labels go from Weak to Strong.
- **Sign-up rules (checked in the browser):** a username is required, the two passwords must match, and the master password needs at least 8 characters.
- **Password generator:** 16 random characters from letters, digits and symbols, using `crypto.getRandomValues`.
- **Copy buttons:** copy a username or password with `navigator.clipboard`.
- **Lock Vault button:** clears the key, token and decrypted entries from memory.
- **Delete confirmation:** asks before deleting an entry permanently.
- **Unreadable entries:** if an entry fails to decrypt, for example because its data was tampered with, it appears as "[Unreadable entry]" instead of breaking the whole vault.
- **Notifications:** react-toastify shows success and error messages at the top center, closing after 3 seconds.

---

## 6. Cryptography (`client/src/vaultCrypto.js`)

| Function | What it does |
|---|---|
| `randomSalt()` | Returns 16 random bytes as 32 hex characters |
| `deriveKeys(password, salt, iterations)` | PBKDF2-SHA256 → 512 bits. Bits 0–255 become `encKey`, an AES-256-GCM `CryptoKey` that is non-extractable. Bits 256–511 become `authKey`, as hex. |
| `encryptEntry(encKey, entry)` | Makes a fresh 12-byte IV and encrypts `JSON.stringify(entry)` with AES-256-GCM. Returns `{ iv, data }` in base64. |
| `decryptEntry(encKey, { iv, data })` | Decrypts and checks the GCM authentication tag. Throws an error if anything was changed. |

`KDF_ITERATIONS = 600000`, OWASP's 2023 recommendation for PBKDF2-SHA256.

```
master password + kdfSalt ──PBKDF2-SHA256 × 600,000──► 512 bits
                                                         ├─ bits 0–255   → encKey  → encrypts entries, never leaves the browser
                                                         └─ bits 256–511 → authKey → sent to server → scrypt(authKey, authSalt) → authHash
```

The two halves are independent: knowing the auth key reveals nothing about the encryption key. So the server can check a login but can't decrypt the vault.

The `data` field holds the ciphertext with the 16-byte GCM authentication tag attached. The IV isn't secret, but a new one is generated for every save and never reused.

---

## 7. Backend (`backend/server.js`)

### Middleware (runs before the routes)

| Order | Middleware | Effect |
|---|---|---|
| 1 | `trust proxy` (only if `TRUST_PROXY` is set) | Rate limiting uses the visitor's real IP |
| 2 | `express.json({ limit: "100kb" })` | Parses JSON bodies and rejects bodies over 100 kB |
| 3 | `cors(...)` | Allows same-origin requests and origins listed in `ALLOWED_ORIGINS` |
| 4 | `authLimiter` on `/api/auth/login` and `/api/auth/register` | 10 attempts per IP per 15 minutes, then 429 "Too many attempts" |
| 5 | `requireAuth` on every `/api/passwords` route | Verifies the JWT and sets `req.userId` |

### Helpers

| Helper | Purpose |
|---|---|
| `normalizeUsername` | Trims and lowercases usernames, so `Kamlesh` and `kamlesh` are the same account |
| `USERNAME_RE` | 3–64 characters: letters, numbers, `_ . @ -` |
| `hashAuthKey(authKey, salt)` | `crypto.scryptSync(authKey, salt, 64)` |
| `fakeSalt(username)` | HMAC-SHA256 of the username with `JWT_SECRET`, cut to 32 hex characters |
| `isValidEntry({ iv, data })` | Both base64; `iv` up to 24 characters; `data` up to 50,000 characters |
| `parseId` | Rejects invalid MongoDB IDs with 400 |
| `requireAuth` | Reads `Authorization: Bearer <token>`, runs `jwt.verify`, sets `req.userId`. Returns 401 if the token is missing, invalid or expired. |

### API reference

**Auth routes** (no token needed)

| Method and path | Request body | Success response | Errors |
|---|---|---|---|
| `POST /api/auth/register` | `{ username, salt, authKey }` | 201 `{ token }` | 400 invalid data, 409 username taken, 429 rate limited |
| `POST /api/auth/prelogin` | `{ username }` | 200 `{ salt, iterations }` (a fake salt for unknown users) | 500 |
| `POST /api/auth/login` | `{ username, authKey }` | 200 `{ token }` | 400 invalid data, 401 wrong username or password, 429 rate limited |

**Vault routes** (all need `Authorization: Bearer <token>`)

| Method and path | Request body | Success response | Errors |
|---|---|---|---|
| `GET /api/passwords` | none | 200 `[{ _id, iv, data }]`, oldest first | 401 |
| `POST /api/passwords` | `{ iv, data }` | 201 `{ success, id }` | 400 invalid entry, 401 |
| `PUT /api/passwords/:id` | `{ iv, data }` | 200 `{ success }` | 400, 401, 404 not found or not yours |
| `DELETE /api/passwords/:id` | none | 200 `{ success }` | 400, 401, 404 not found or not yours |

Server errors are logged on the server, and the client gets a short generic message, so internal details aren't leaked.

---

## 8. Database (MongoDB Atlas, database `secureKeep`)

### `users` collection

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | |
| `username` | string | Lowercase, **unique index** |
| `kdfSalt` | string | 16 bytes as hex, generated by the browser |
| `kdfIterations` | number | 600000, stored per user so it can be raised later |
| `authSalt` | string | 16 bytes as hex, generated by the server |
| `authHash` | string | `scrypt(authKey, authSalt)`, 64 bytes as hex |
| `createdAt` | Date | |

### `passwords` collection

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | |
| `userId` | ObjectId | Owner, points to `users._id`, **indexed** |
| `iv` | string | 12 bytes, base64 |
| `data` | string | AES-GCM ciphertext and tag, base64. Contains site, username and password. |
| `createdAt`, `updatedAt` | Date | |

Relationship: one user has many entries.

Every vault query filters on `userId` from the verified JWT, never from the request body. Update and delete filter on `{ _id, userId }` together, so another user's entry ID matches nothing and returns 404. This blocks IDOR attacks.

The database never contains a master password, an encryption key, a raw auth key, or any readable site name or password.

---

## 9. End-to-end flows

### Sign up

```
Browser                                         Server                                   MongoDB
───────                                         ──────                                   ───────
1. Check username, matching passwords, 8+ chars
2. salt = randomSalt()
3. deriveKeys(password, salt) → encKey, authKey
4. POST /api/auth/register ───────────────────► 5. Validate username, salt, authKey
   { username, salt, authKey }                     authSalt = randomBytes(16)
                                                   authHash = scrypt(authKey, authSalt)
                                                   insertOne(user) ───────────────────► users
                                                   (duplicate username → 409)
                                                6. jwt.sign({ sub: userId }, 1 h)
7. Keep encKey + token in memory ◄─────────────── 201 { token }
8. Save username in localStorage, open vault, load entries
```

### Log in

```
Browser                                         Server                                   MongoDB
───────                                         ──────                                   ───────
1. POST /api/auth/prelogin { username } ──────► 2. findOne({ username }) ──────────────► users
3. ◄──────────────────────────────────────────── { salt, iterations }
                                                   (unknown user → fake salt, same shape)
4. deriveKeys(password, salt, iterations) → encKey, authKey
5. POST /api/auth/login ──────────────────────► 6. Rate limit check
   { username, authKey }                           findOne({ username }) ──────────────► users
                                                   scrypt(authKey, authSalt) vs authHash
                                                   timingSafeEqual (dummy compare if unknown)
7. ◄──────────────────────────────────────────── 200 { token }  or  401
8. GET /api/passwords + Bearer ───────────────► 9. requireAuth → userId
                                                   find({ userId }) ───────────────────► passwords
10. ◄─────────────────────────────────────────── [{ _id, iv, data }]
11. decryptEntry() for each → show the vault table
```

### Add or edit an entry

```
Browser                                         Server                                   MongoDB
───────                                         ──────                                   ───────
1. User fills site, username, password
2. encryptEntry(encKey, entry) → { iv, data }   (a new IV every time, edits included)
3. POST /api/passwords        ────────────────► 4. requireAuth → userId
   or PUT /api/passwords/:id                       isValidEntry(body)
   { iv, data } + Bearer                           insertOne({ userId, iv, data, ... }) ─► passwords
                                                   or updateOne({ _id, userId }, ...)
5. ◄──────────────────────────────────────────── 201 / 200   (PUT on another user's id → 404)
6. Re-fetch and decrypt the list
```

### Delete an entry

The browser confirms with the user, then sends `DELETE /api/passwords/:id` with the bearer token. The server runs `deleteOne({ _id, userId })`. It returns 200, or 404 if the entry doesn't exist or belongs to someone else. The browser then re-fetches the list.

### Session expiry and locking

- The JWT expires after 1 hour. The next vault call gets 401, and `authFetch` locks the vault automatically.
- **Lock Vault**, a page refresh, or closing the tab clears the key, token and decrypted entries from memory.

---

## 10. Security summary

| Threat | Protection |
|---|---|
| Database leak | Only ciphertext and scrypt hashes are stored. Each master password guess costs 600,000 PBKDF2 rounds. |
| Curious server admin | Sees the auth key at login, which can't produce the encryption key |
| Online password guessing | 10 attempts per IP per 15 minutes on login and sign-up |
| Username enumeration | Fake deterministic salt from `/prelogin`, dummy hash comparison and the same error message at `/login` |
| Timing attacks | `crypto.timingSafeEqual` for hash comparison |
| Accessing another user's data (IDOR) | Every query is scoped to `userId` from the JWT; returns 404, not 403 |
| Tampered ciphertext | AES-GCM tag check makes decryption fail |
| Forged or changed tokens | JWT signature check with `JWT_SECRET` |
| Stolen token | Kept in memory only and expires in 1 hour |
| Oversized or malformed input | 100 kB body cap, regex, hex and base64 checks, size limits |
| Cross-site API calls | CORS allowlist |
| Leaked secrets | `.env` is in `.gitignore` |

---

## 11. Known limitations

- **No password recovery.** A forgotten master password means the vault is lost. This is by design.
- **No refresh tokens or revocation.** A stolen JWT works until it expires.
- **In-memory rate limiter.** Counts reset when the server restarts and aren't shared between server instances; Redis would fix both.
- **`/prelogin` isn't rate limited.** It only returns a salt, real or fake, so nothing useful leaks.
- **Sign-up reveals taken usernames** through the 409 error. This is normal for usability, and rate limiting slows mass checks.
- **No master password change** or account deletion yet.
- **A compromised server could serve malicious JavaScript.** This applies to every web-based zero-knowledge app.
- **No automated tests yet.**

---

## 12. Legacy migration (`backend/migrate-legacy.js`)

Version 1 of SecureKeep had no user accounts. It encrypted entries with CryptoJS AES using a PBKDF2 key (10,000 iterations) and kept the salt in browser localStorage. The migration script moves those entries into a v2 account:

1. Create an account in the current app.
2. In the browser you used for v1, open the console (F12) and run `localStorage.getItem("salt")` to get the old salt.
3. Run `node migrate-legacy.js` in `backend/`. Add `--delete-old` to also remove the old entries after a successful migration.
4. Enter the new username and master password, the old master password, and the old salt when asked.

The script rebuilds the old key, decrypts each entry by reimplementing CryptoJS's `Salted__` format and MD5 key derivation, and re-encrypts it with the v2 scheme into the new account.

---

## 13. Running the project

**Prerequisites:** Node.js 18 or newer, and a MongoDB Atlas cluster with your IP added under **Network Access**.

```powershell
# Install dependencies (once)
cd backend; npm install
cd ../client; npm install

# Terminal 1: backend
cd backend
npm run dev        # wait for "Connected to MongoDB successfully"

# Terminal 2: frontend
cd client
npm run dev        # open http://localhost:5173
```

**Troubleshooting**

| Symptom | Cause | Fix |
|---|---|---|
| "Could not reach the server" | Backend isn't running | Check terminal 1 for errors |
| `MongoServerSelectionError ... SSL alert number 80` | Atlas is blocking your IP, or the cluster is paused | Add your IP in Atlas **Network Access**, or resume the cluster |
| "MONGODB_URI and JWT_SECRET must be set" | `backend/.env` is missing or incomplete | Add both values |
| "Too many attempts" | Rate limit reached | Wait 15 minutes, or restart the backend |
| "Session expired" | The JWT is older than 1 hour | Log in again |

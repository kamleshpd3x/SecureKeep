# 🔒 SecureKeep Password Manager

A secure, client-side encrypted password manager that keeps your credentials safe while providing a clean, intuitive interface.

## 🛡️ Features

-   **Client-side encryption** - All sensitive data is encrypted in your browser before storage
-   **Zero-knowledge architecture** - Your master password never leaves your device
-   **Strong encryption** - Uses industry-standard AES-256 encryption via CryptoJS
-   **PBKDF2 key derivation** - Protects against brute force attacks
-   **Password strength meter** - Helps you create strong master passwords
-   **Password generator** - Creates strong, random passwords with a single click
-   **Modern React UI** - Clean, responsive interface built with React and Tailwind CSS
-   **Secure by design** - No passwords are stored in plaintext at any point

## 🚀 Quick Start

### Prerequisites

-   Node.js (v18+)
-   MongoDB (local or Atlas)

### Installation

1. Clone the repository

```bash
git clone https://github.com/kamleshpd3x/SecureKeep-AES-256.git
cd SecureKeep
```

2. Install dependencies

```bash
cd backend && npm install
cd ../client && npm install
```

3. Create `backend/.env` with:

```
PORT=3000
MONGODB_URI=mongodb://localhost:27017
JWT_SECRET=a-long-random-string
# Optional: comma-separated origins allowed to call the API cross-origin
ALLOWED_ORIGINS=
```

4. Start the development servers

```bash
# In one terminal, start the backend (auto-restarts on changes)
cd backend
npm run dev

# In another terminal, start the frontend
cd client
npm run dev
```

5. Open your browser to http://localhost:5173

### Production

Build the frontend with `cd client && npm run build`, then start the backend with `cd backend && npm start`. The backend serves the built app and the API from one origin. Serve it over HTTPS: browsers only allow the Web Crypto API on HTTPS or `localhost`.

## 🔐 How It Works

1. **Registration**: You pick a username and master password. The browser generates a random salt.
2. **Key derivation**: PBKDF2-SHA256 (600,000 iterations) turns the master password into 512 bits. The first half is an AES-256-GCM encryption key that never leaves the browser; the second half is an auth key.
3. **Authentication**: Only the auth key is sent to the server, which stores a salted scrypt hash of it and issues a 1-hour JWT on login.
4. **Data storage**: Each entry (site, username, password) is encrypted in the browser with AES-GCM. The server stores only `{ userId, iv, ciphertext }`.
5. **Any device**: The salt is stored on the server, so you can unlock your vault from any browser.

## 🧠 Technical Details

### Security Model

-   **Client-side encryption**: All encryption/decryption happens in the browser
-   **Key derivation**: PBKDF2-SHA256 with 600,000 iterations (Web Crypto API)
-   **AES-256-GCM encryption**: Authenticated encryption with a random IV per entry
-   **Per-user isolation**: Every API route requires a JWT and only touches that user's entries
-   **CORS allowlist**: Only origins in `ALLOWED_ORIGINS` may call the API cross-origin
-   **Rate limiting**: Login and registration are limited to 10 attempts per IP per 15 minutes
-   **No password recovery**: If you forget your master password, your data cannot be recovered

### Tech Stack

-   **Frontend**: React, Tailwind CSS, Web Crypto API
-   **Backend**: Node.js, Express
-   **Database**: MongoDB
-   **API**: RESTful JSON API
-   **Authentication**: Derived auth key + scrypt hash on server + JWT sessions

## 📱 Roadmap

-   [ ] Mobile application
-   [ ] Browser extensions
-   [ ] Biometric authentication
-   [ ] Multi-factor authentication
-   [ ] Shared vaults for team use
-   [ ] Password health analysis
-   [ ] Audit logging
-   [ ] Password expiration reminders

## 🔧 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

This is a demonstration project. While it implements proper encryption techniques, it has not undergone professional security auditing. Use at your own risk for production environments.

---

Made with ❤️ by [Kamalesh Prasad]

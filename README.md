# 🔐 Secure File Storage System

A production-ready secure cloud file storage application** built using Flask, implementing AES-256 encryption**, OTP-based authentication, and OWASP Top-10 security hardening.

This project demonstrates secure system design, backend security, and real-world deployment practices.

---

## 🚀 Key Features

- 🔑 Email OTP-based user authentication
- 🔐 AES-256 encryption for stored files
- 📂 Secure file upload & download
- 🔗 Time-limited secure file sharing links
- 📏 File size & type validation
- 🚦 Rate limiting with Redis (brute-force protection)
- 🛡️ OWASP Top-10 security hardening
- ⚙️ Production deployment with Gunicorn & systemd

---

## 🛠️ Tech Stack

| Layer | Technology |
|-----|-----------|
| Backend | Python (Flask) |
| Encryption | AES-256 (Fernet) |
| Authentication | Email OTP |
| Database | SQLite |
| Rate Limiting | Flask-Limiter + Redis |
| WSGI Server | Gunicorn |
| Reverse Proxy | Nginx |
| OS | Kali Linux / Linux |

---

## 🔐 Security Implementation

This project is hardened against **OWASP Top-10 vulnerabilities**:

- ✔ Secure authentication & session handling
- ✔ Password hashing (Werkzeug)
- ✔ Rate limiting to prevent brute-force attacks
- ✔ File validation to prevent malicious uploads
- ✔ Secure headers (CSP, XSS, Clickjacking protection)
- ✔ Encrypted file storage (AES-256)
- ✔ Secure share links with expiry
- ✔ Access control enforcement

---

## 🧪 Application Flow

1. User registers using email
2. OTP verification required for account activation
3. User logs in securely
4. Files are uploaded and encrypted
5. Encrypted files stored on server
6. Secure share link generated (time-bound)
7. File auto-expires after share duration

---

## ▶️ How to Run (Production Mode)

```bash
source venv/bin/activate
sudo systemctl start securefilestorage

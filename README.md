# CyberShield AI

> **Web Penetration Testing & Security Assessment Platform**

CyberShield AI is a modern, modular cybersecurity platform combining web vulnerability scanning, deterministic threat analysis, and interactive security playgrounds in a unified dark-mode dashboard.

---

## 🌐 Live Demo

- **Frontend**: https://cyber-shield-ai-beta-topaz.vercel.app/
- **Backend**: https://cybershield-ai-beta.onrender.com/

---

## 🛡️ Key Features

- **Website Security Scanner**: Analyze web headers, SSL/TLS configurations, CORS policies, and common vulnerability surface areas.
- **Phishing Email Detector**: Deterministic heuristic analysis for phishing language, urgency signals, credential requests, suspicious links, and uncommon TLDs. (ML integration planned — see `backend/app/ml/phishing_detector.py`)
- **Password Strength Analyzer**: Entropy calculation, pattern detection, dictionary matching, common-password signals, and exposure analysis.
- **Log Analyzer**: Deterministic rule-based parsing and anomaly detection for server access logs (failed auth, SQLi, path traversal, XSS probes, scanning agents). (ML integration planned — see `backend/app/ml/log_analyzer.py`)
- **Cryptography Lab**: Browser-native Web Crypto API modules — SHA-256/SHA-512 hashing, Base64/Hex encoding, AES-256-GCM authenticated encryption (PBKDF2-HMAC-SHA256, 600k iterations), HMAC-SHA256 signing/verification, and CSPRNG secure randomness. All operations run locally; nothing leaves the browser.
- **SQL Injection Playground**: Controlled environment for learning and demonstrating SQL injection risks and parameterized query defenses.
- **Security Dashboard**: Real-time visualization of scan results, threat levels, and security metrics.
- **PDF Report Generator**: Automated generation of comprehensive, exportable security audit reports from saved scan history.
- **Tutorials / Cyber Academy**: Guided documentation for every tool — what it does, how to use it, how to read results, and what happens under the hood. Covers Website Scanner, Phishing Detector, Password Analyzer, Log Analyzer, Reports, and Cryptography Lab.

---

## 🏗️ Architecture & Tech Stack

```text
              React + TypeScript (Vercel)
                  │              │
    (Supabase Auth)      (REST API + JWT)
                  │              │
                  ▼              ▼
         Supabase Auth       Flask (Render)
                  │              │
                  └──────┬───────┘
                 Supabase (PostgreSQL)
```

- **Frontend**: React, TypeScript, Vite, Tailwind CSS, Chart.js
- **Backend**: Python, Flask, Flask-CORS, PyJWT, bcrypt, cryptography, requests, python-dotenv, gunicorn
- **Authentication**: Supabase Auth (`auth.users`) — React signs up / signs in / signs out directly; Flask verifies the Supabase access JWT
- **Application user data**: `public.profiles` linked 1:1 to `auth.users.id`
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib (training pipeline scaffolded; models not loaded in production)
- **Database**: Supabase (PostgreSQL)
- **Deployment**: Vercel (Frontend), Render (Backend)

---

## 📁 Repository Structure

```text
CyberShield-AI/
├── frontend/        # React + TypeScript Vite frontend application
├── backend/         # Flask REST API server and business modules
├── docs/            # Single source of truth documentation
├── datasets/        # Placeholder directories for future ML training data (emails, logs, passwords, urls)
├── models/          # Placeholder directory for trained scikit-learn models (.pkl) — currently only .placeholder files
├── branding/        # Brand guidelines, logos, color palettes, fonts
├── assets/          # Project images, animations, and screenshots
└── prompts/         # Structured AI prompts for system development
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js (v18+) & npm
- Python (v3.10+) & pip
- Supabase Account

### Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Amatrasu66/CyberShield-AI_beta.git
   cd CyberShield-AI_beta
   ```

2. **Frontend Setup**:
   ```bash
   cd frontend
   npm install
   cp .env.example .env
   npm run dev
   ```

3. **Backend Setup**:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   cp .env.example .env
   python app.py
   ```

---

## 📄 Documentation

All detailed specifications, architecture diagrams, API schemas, and guidelines are located in the [`docs/`](docs/) directory.

---

## 🔒 Security & Compliance

This platform is strictly built for authorized testing, educational demonstrations, and risk assessments. Always obtain proper authorization before scanning external endpoints.
# CyberShield AI

> **Intelligent Web Penetration Testing & Security Assessment Platform**

CyberShield AI is a modern, modular cybersecurity platform designed to combine web vulnerability scanning, AI-powered threat detection, and interactive security playgrounds in a unified dark-mode dashboard.

---

## 🌐 Live Demo

- **Frontend**: https://cyber-shield-ai-beta-topaz.vercel.app/
- **Backend**: https://cybershield-ai-beta.onrender.com/

---

## 🛡️ Key Features

- **Website Security Scanner**: Analyze web headers, SSL/TLS configurations, CORS policies, and common vulnerability surface areas.
- **Phishing Email Detector (AI)**: Machine learning classification engine (Naive Bayes / TF-IDF) to detect phishing emails and malicious content.
- **Password Strength Analyzer**: Entropy calculation, pattern detection, dictionary matching, and exposure analysis.
- **Log Analyzer (AI)**: Automated parsing and anomaly detection for server access logs and security events.
- **Cryptography Lab**: Interactive exploration of modern symmetric/asymmetric encryption, hashing, and encoding schemes.
- **SQL Injection Playground**: Controlled environment for learning and demonstrating SQL injection risks and parameterized query defenses.
- **Security Dashboard**: Real-time visualization of scan results, threat levels, and security metrics.
- **PDF Report Generator**: Automated generation of comprehensive, exportable security audit reports.

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
                      │
             ML Models (.pkl)
```

- **Frontend**: React, TypeScript, Vite, Tailwind CSS, Chart.js
- **Backend**: Python, Flask, Flask-CORS, PyJWT, bcrypt, cryptography, requests, python-dotenv, gunicorn
- **Authentication**: Supabase Auth (`auth.users`) — React signs up / signs in / signs out directly; Flask verifies the Supabase access JWT
- **Application user data**: `public.profiles` linked 1:1 to `auth.users.id`
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
- **Database**: Supabase (PostgreSQL)
- **Deployment**: Vercel (Frontend), Render (Backend)

---

## 📁 Repository Structure

```text
CyberShield-AI/
├── frontend/        # React + TypeScript Vite frontend application
├── backend/         # Flask REST API server and business modules
├── docs/            # Single source of truth documentation
├── datasets/        # Datasets for ML training (emails, logs, passwords, urls)
├── models/          # Trained scikit-learn models (.pkl)
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
   cd CyberShield-AI
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

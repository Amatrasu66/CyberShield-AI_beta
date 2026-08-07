# CyberShield AI - Backend API Service

Flask-based REST API service for CyberShield AI platform.

## Architecture

The backend follows a modular layer architecture:

- `app.py`: Entry point for application initialization.
- `app/routes/`: Flask Blueprint routes handling HTTP requests and responses.
- `app/services/`: Core domain and business logic processing.
- `app/models/`: Data models and schema definitions.
- `app/database/`: Supabase PostgreSQL client and SQL migration scripts.
- `app/ml/`: Machine learning inference wrappers and model loaders.
- `app/utils/`: Security utilities, validation logic, and shared helper modules.
- `app/middleware/`: Authentication checks, CORS setup, and error handling.
- `app/config/`: App environment configurations.
- `app/reports/`: PDF report rendering via ReportLab.

## Setup & Running

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Environment Variables:
   ```bash
   cp .env.example .env
   ```

4. Run local server:
   ```bash
   python app.py
   ```

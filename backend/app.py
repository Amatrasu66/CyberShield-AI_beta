"""
CyberShield AI - Flask application entry point.

Loads environment variables, creates the app via the application factory, and
starts the development server.

Run locally:
    python app.py
"""

from dotenv import load_dotenv

from app import create_app

load_dotenv()

app = create_app()

if __name__ == "__main__":
    # The debug flag defaults to False; set FLASK_DEBUG=1 for hot reload.
    debug = str(app.config.get("DEBUG", False)).lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=int(app.config.get("PORT", 5000)), debug=debug)

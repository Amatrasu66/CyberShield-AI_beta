"""
Application Configuration Settings (Placeholder)
Loads environment variables for Flask app, database connections, and model parameters.
"""

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-secret-key')
    SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
    PHISHING_MODEL_PATH = os.environ.get('PHISHING_MODEL_PATH', '../models/phishing_model.pkl')
    LOG_MODEL_PATH = os.environ.get('LOG_MODEL_PATH', '../models/log_analyzer.pkl')

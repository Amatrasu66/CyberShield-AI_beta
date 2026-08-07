"""
User Model Schema & Data Layer (Placeholder)
"""

class User:
    def __init__(self, user_id=None, email=None, password_hash=None, created_at=None):
        self.user_id = user_id
        self.email = email
        self.password_hash = password_hash
        self.created_at = created_at

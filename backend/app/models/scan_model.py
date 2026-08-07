"""
Scan Model Schema & Data Layer (Placeholder)
Covers website_scans, email_scans, password_scans, and log_scans.
"""

class Scan:
    def __init__(self, scan_id=None, user_id=None, scan_type=None, result=None, created_at=None):
        self.scan_id = scan_id
        self.user_id = user_id
        self.scan_type = scan_type
        self.result = result
        self.created_at = created_at

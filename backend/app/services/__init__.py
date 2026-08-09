"""
Services package: core domain and business logic.

Each service is a thin facade over deterministic domain logic. Routes stay thin
and delegate here. Database access (Supabase) and ML inference will be injected
through these services in later phases without changing route contracts.
"""

from .auth_service import AuthService
from .crypto_service import CryptoService
from .email_service import EmailService
from .log_service import LogService
from .password_service import PasswordService
from .report_service import ReportService
from .scanner_service import ScannerService
from .sql_service import SQLPlaygroundService

__all__ = [
    "AuthService",
    "CryptoService",
    "EmailService",
    "LogService",
    "PasswordService",
    "ReportService",
    "ScannerService",
    "SQLPlaygroundService",
]

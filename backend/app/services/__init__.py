"""
Services package: core domain and business logic.

Each service is a thin facade over deterministic domain logic. Routes stay thin
and delegate here. Database access (Supabase) and ML inference will be injected
through these services in later phases without changing route contracts.
"""

from .auth_service import AuthService
from .crypto_service import CryptoService
from .dashboard_service import DashboardService
from .email_service import EmailService
from .log_service import LogService
from .password_service import PasswordGenerator, PasswordService
from .ip_reputation_service import IPReputationService, ReputationResult
from .port_scanner_service import PortScannerService
from .report_service import ReportService
from .scanner_service import ScannerService
from .sql_service import SQLPlaygroundService

__all__ = [
    "AuthService",
    "CryptoService",
    "DashboardService",
    "EmailService",
    "IPReputationService",
    "LogService",
    "PasswordGenerator",
    "PasswordService",
    "PortScannerService",
    "ReputationResult",
    "ReportService",
    "ScannerService",
    "SQLPlaygroundService",
]

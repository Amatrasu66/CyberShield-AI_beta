"""
Reports package.

- PDF generation via ``app/reports/pdf_generator.py``.
- Supabase Storage integration for generated PDFs via
  ``app/reports/storage.py``.
"""

from .storage import ReportStorageService

__all__ = ["ReportStorageService"]

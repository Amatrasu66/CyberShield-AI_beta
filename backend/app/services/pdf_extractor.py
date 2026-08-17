"""
PDF upload handling for the Phishing Email Detector.

Validates an uploaded email PDF and extracts its text using ``pypdf``. The
extracted text is fed into the existing email analysis pipeline
(:meth:`EmailService.analyze_email`) exactly like pasted email content, so the
same analyzer and the same response structure are reused.

No OCR is performed: PDFs containing only images/scanned screenshots (no text
layer) cannot be analyzed and are rejected with a clear validation error.

Uploaded PDF files are never stored. The extracted text is treated exactly like
pasted email content: it is never persisted and never logged.
"""

from io import BytesIO

from pypdf import PdfReader

from ..errors import PayloadTooLargeError, ValidationError

NO_TEXT_MESSAGE = (
    "Could not extract text from this PDF. "
    "Please upload a text-based email PDF or paste the email text."
)

_PDF_PREFIX = b"%PDF-"


def _effective_max_size(config) -> int:
    """Effective upload ceiling: the PDF limit capped by the global body limit."""
    pdf_limit = int(config.get("EMAIL_PDF_MAX_SIZE", 1_000_000) or 1_000_000)
    body_limit = int(config.get("MAX_CONTENT_LENGTH", 1_000_000) or 1_000_000)
    return max(1, min(pdf_limit, body_limit))


def _normalize(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    return "\n".join(lines)


def extract_pdf_email(file_storage, config) -> str:
    """Validate an uploaded PDF and return its extracted text.

    Raises :class:`ValidationError` (or :class:`PayloadTooLargeError`) with a
    clear message when the upload is missing, the wrong type, too large, not a
    valid PDF, or contains no extractable text.
    """
    filename = (file_storage.filename or "").strip()
    if not filename.lower().endswith(".pdf"):
        raise ValidationError(
            "Please upload a PDF file", details={"field": "file", "allowed": "application/pdf"}
        )

    data_bytes = file_storage.read()
    if not data_bytes:
        raise ValidationError("The uploaded PDF is empty", details={"field": "file"})

    max_size = _effective_max_size(config)
    if len(data_bytes) > max_size:
        raise PayloadTooLargeError(
            f"PDF exceeds the maximum size of {max_size} bytes",
            details={"field": "file", "max_bytes": max_size, "size_bytes": len(data_bytes)},
        )

    if not data_bytes.startswith(_PDF_PREFIX):
        raise ValidationError(
            "The uploaded file is not a valid PDF", details={"field": "file"}
        )

    try:
        reader = PdfReader(BytesIO(data_bytes))
    except Exception:
        raise ValidationError(
            "The uploaded file is not a valid PDF", details={"field": "file"}
        )

    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            raise ValidationError(NO_TEXT_MESSAGE, details={"field": "file"})

    pages = []
    for page in reader.pages:
        try:
            page_text = page.extract_text() or ""
        except Exception:
            page_text = ""
        pages.append(_normalize(page_text))

    text = "\n".join(pages).strip()
    if not text:
        raise ValidationError(NO_TEXT_MESSAGE, details={"field": "file"})

    max_length = int(config.get("EMAIL_MAX_LENGTH", 50_000) or 50_000)
    if len(text) > max_length:
        raise ValidationError(
            f"Extracted email exceeds the maximum length of {max_length} characters",
            details={"field": "file", "max_length": max_length},
        )

    return text
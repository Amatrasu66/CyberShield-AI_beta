"""Tests for the Supabase Storage report storage service.

The Supabase admin client is mocked end-to-end: ``storage.from_(...)`` returns a
fake bucket that records uploads and signed-URL requests. No network traffic is
ever involved.
"""

import pytest

from app.errors import ServiceUnavailableError, ValidationError
from app.reports.storage import ReportStorageService

CONFIG = {
    "REPORT_STORAGE_BUCKET": "report-pdfs",
    "REPORT_SIGNED_URL_EXPIRES": 7200,
}


class _FakeBucket:
    """Deterministic in-memory stand-in for a Supabase Storage bucket."""

    def __init__(self, bucket_id):
        self.id = bucket_id
        self.uploads = []
        self.signed_requests = []
        self.public_url_calls = 0
        self.fail_upload = False
        self.fail_signed_url = False

    def upload(self, path, file, file_options=None):
        if self.fail_upload:
            raise ConnectionError("upload failed")
        self.uploads.append((path, file, file_options))
        return {"path": path, "Key": path}

    def create_signed_url(self, path, expires_in, options=None):
        if self.fail_signed_url:
            raise ConnectionError("signing failed")
        self.signed_requests.append((path, expires_in, options))
        url = f"https://storage.example/{path}?token=abc"
        return {"signedURL": url, "signedUrl": url}

    def get_public_url(self, *args, **kwargs):
        self.public_url_calls += 1
        return "https://storage.example/public/"


class _FakeStorage:
    def __init__(self, bucket):
        self.bucket = bucket

    def from_(self, bucket_id):
        assert bucket_id == self.bucket.id
        return self.bucket


class _FakeAdminClient:
    def __init__(self, bucket):
        self.storage = _FakeStorage(bucket)


@pytest.fixture()
def storage_harness(monkeypatch):
    bucket = _FakeBucket(CONFIG["REPORT_STORAGE_BUCKET"])
    admin_client = _FakeAdminClient(bucket)
    monkeypatch.setattr(
        "app.reports.storage.get_supabase_admin_client", lambda: admin_client
    )
    return admin_client, bucket


class TestObjectPath:
    def test_joins_user_and_report_id(self):
        assert ReportStorageService.object_path("user-1", "report-1") == "user-1/report-1.pdf"

    def test_rejects_empty_segments(self):
        with pytest.raises(ValidationError):
            ReportStorageService.object_path("", "report-1")
        with pytest.raises(ValidationError):
            ReportStorageService.object_path("user-1", "")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValidationError):
            ReportStorageService.object_path("../other", "report-1")
        with pytest.raises(ValidationError):
            ReportStorageService.object_path("user-1", "..")
        with pytest.raises(ValidationError):
            ReportStorageService.object_path("user-1", "a/b")
        with pytest.raises(ValidationError):
            ReportStorageService.object_path("user-1", "a\\b")


class TestUploadPdf:
    def test_uploads_and_returns_signed_url(self, storage_harness):
        _, bucket = storage_harness
        pdf = b"%PDF-1.4 fake"

        result = ReportStorageService.upload_pdf(pdf, "user-1", "report-1", config=CONFIG)

        assert result == {
            "storage_path": "user-1/report-1.pdf",
            "signed_url": "https://storage.example/user-1/report-1.pdf?token=abc",
        }
        assert bucket.uploads == [(
            "user-1/report-1.pdf",
            pdf,
            {"content-type": "application/pdf"},
        )]
        assert bucket.signed_requests == [("user-1/report-1.pdf", 7200, None)]

    def test_uses_server_only_admin_client(self, storage_harness):
        admin_client, _ = storage_harness
        result = ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1", config=CONFIG)
        assert result["storage_path"] == "user-1/report-1.pdf"
        assert admin_client.storage.bucket.uploads

    def test_never_uses_public_url(self, storage_harness):
        _, bucket = storage_harness
        ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1", config=CONFIG)
        assert bucket.public_url_calls == 0

    def test_uses_configured_expiry(self, storage_harness):
        _, bucket = storage_harness
        ReportStorageService.upload_pdf(
            b"%PDF", "user-1", "report-1",
            config={"REPORT_STORAGE_BUCKET": "report-pdfs"},
        )
        assert bucket.signed_requests == [("user-1/report-1.pdf", 3600, None)]

    def test_uses_app_config_when_config_not_given(self, app, storage_harness):
        _, bucket = storage_harness
        app.config["REPORT_STORAGE_BUCKET"] = "report-pdfs"
        app.config["REPORT_SIGNED_URL_EXPIRES"] = 9999

        result = ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1")

        assert result["storage_path"] == "user-1/report-1.pdf"
        assert bucket.signed_requests == [("user-1/report-1.pdf", 9999, None)]

    def test_bucket_unconfigured_raises(self, storage_harness):
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1", config={})
        assert exc.value.status_code == 503
        assert exc.value.code == "STORAGE_UNAVAILABLE"

    def test_missing_admin_client_raises(self, monkeypatch):
        monkeypatch.setattr("app.reports.storage.get_supabase_admin_client", lambda: None)
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1", config=CONFIG)
        assert exc.value.code == "STORAGE_UNAVAILABLE"

    def test_upload_failure_raises(self, storage_harness):
        _, bucket = storage_harness
        bucket.fail_upload = True
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1", config=CONFIG)
        assert exc.value.code == "STORAGE_UPLOAD_FAILED"
        assert exc.value.details["path"] == "user-1/report-1.pdf"

    def test_signed_url_failure_raises(self, storage_harness):
        _, bucket = storage_harness
        bucket.fail_signed_url = True
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1", config=CONFIG)
        assert exc.value.code == "STORAGE_SIGNED_URL_FAILED"

    def test_missing_signed_url_raises(self, storage_harness):
        _, bucket = storage_harness

        def _no_url(path, expires_in, options=None):
            bucket.signed_requests.append((path, expires_in, options))
            return {"signedURL": None, "signedUrl": None}

        bucket.create_signed_url = _no_url
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportStorageService.upload_pdf(b"%PDF", "user-1", "report-1", config=CONFIG)
        assert exc.value.code == "STORAGE_SIGNED_URL_FAILED"

    def test_invalid_ids_raise(self, storage_harness):
        with pytest.raises(ValidationError):
            ReportStorageService.upload_pdf(b"%PDF", "../evil", "report-1", config=CONFIG)
        with pytest.raises(ValidationError):
            ReportStorageService.upload_pdf(b"%PDF", "user-1", "", config=CONFIG)


class TestGetSignedUrl:
    def test_returns_url_with_configured_expiry(self, storage_harness):
        _, bucket = storage_harness
        url = ReportStorageService.get_signed_url("user-1", "report-1", config=CONFIG)
        assert url == "https://storage.example/user-1/report-1.pdf?token=abc"
        assert bucket.signed_requests == [("user-1/report-1.pdf", 7200, None)]

    def test_signing_failure_raises(self, storage_harness):
        _, bucket = storage_harness
        bucket.fail_signed_url = True
        with pytest.raises(ServiceUnavailableError) as exc:
            ReportStorageService.get_signed_url("user-1", "report-1", config=CONFIG)
        assert exc.value.code == "STORAGE_SIGNED_URL_FAILED"

    def test_invalid_ids_raise(self, storage_harness):
        with pytest.raises(ValidationError):
            ReportStorageService.get_signed_url("..", "report-1", config=CONFIG)

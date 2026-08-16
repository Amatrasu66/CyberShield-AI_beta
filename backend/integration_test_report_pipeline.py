"""
REAL end-to-end report pipeline integration test.

Runs against the RUNNING Flask server (http://localhost:5000) and the REAL
Supabase project configured in ``.env``. No Supabase/Storage mocks are used.

Pipeline exercised:
  1. Sign in the CyberShield test user against real Supabase Auth.
  2. POST /api/reports/generate with the real access token (Bearer).
  3. Assert the report aggregates the user's REAL persisted scan data.
  4. Verify ReportLab produced a real PDF.
  5. Verify the PDF was uploaded to the REAL private ``report-pdfs`` bucket.
  6. Verify ``storage_path`` uses the ownership-safe ``<user_id>/<report_id>.pdf``.
  7. Verify a row was inserted into REAL ``public.reports``.
  8. Verify the signed URL can actually retrieve/read the PDF.
  9. Verify GET /api/reports returns the created report with a working signed URL.
 10. Verify a DIFFERENT real user's JWT cannot access the report or its
     Storage object (RLS on ``reports``, no un-signed storage access).
 11. Check whether live ``log_scans.risk_level`` matches the schema.

NEVER prints/saves/logs the test password or any access token.

Nothing is deleted until every verification has completed. After that, only
artifacts created by THIS test are removed (the constraint probe row and the
synthetic second user). The generated report is left in place.
"""

import getpass
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(BASE_DIR / ".env")

from app.config.settings import Config  # noqa: E402
from app.database.supabase_client import _build_client, _publishable_key  # noqa: E402

RESULTS = {}
NOTES = []


def record(name: str, passed: bool, detail: str = ""):
    RESULTS[name] = passed
    tag = "PASS" if passed else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if detail else ""))


def _redact_url(url: str) -> str:
    return url if not url else (url[:60] + "...") if len(url) > 60 else url


def _is_pdf(data: bytes) -> bool:
    return data.startswith(b"%PDF-") and b"%%EOF" in data and len(data) > 1000


def _decode_sub(token: str) -> str:
    import jwt

    return jwt.decode(token, options={"verify_signature": False})["sub"]


def main() -> int:
    cfg = Config

    supabase_url = (cfg.SUPABASE_URL or "").strip()
    anon_key = _publishable_key()
    secret_key = (cfg.SUPABASE_SECRET_KEY or "").strip()
    bucket = (cfg.REPORT_STORAGE_BUCKET or "").strip() or "report-pdfs"

    base = os.environ.get("CS_BASE_URL", "http://localhost:5000").rstrip("/")
    if not supabase_url:
        print("[ERROR] SUPABASE_URL is not set in .env")
        return 2

    email = os.environ.get("CS_TEST_USER_EMAIL", "").strip()
    password = os.environ.get("CS_TEST_USER_PASSWORD", "")
    if not email:
        email = input("Test user email: ").strip()
    if not password:
        password = getpass.getpass("Test user password: ")
    if not email or not password:
        print("[ERROR] Test user email/password required")
        return 2

    print(f"=== REAL end-to-end report pipeline test ===")
    print(f"Backend: {base}")
    print(f"Supabase: {supabase_url} | bucket: {bucket}")

    # ------------------------------------------------------------------ 0
    print("\n[1] Server readiness + sign in the real test user")
    try:
        health = requests.get(f"{base}/api/health", timeout=10)
        server_ok = health.status_code == 200 and health.json().get("success") is True
    except Exception as exc:  # noqa: BLE001
        server_ok = False
        NOTES.append(f"health endpoint failed: {type(exc).__name__}")
    record("SERVER_UP", server_ok)
    if not server_ok:
        print("[ERROR] Server is not reachable. Start it with `python app.py`.")
        return 2

    client = _build_client(supabase_url, anon_key)
    admin = _build_client(supabase_url, secret_key)
    if client is None or admin is None:
        print("[ERROR] Supabase clients could not be built (missing keys?)")
        return 2

    try:
        auth_resp = client.auth.sign_in_with_password({"email": email, "password": password})
    except Exception as exc:  # noqa: BLE001
        record("SIGN_IN", False, f"{type(exc).__name__}: {exc}")
        return 1
    session = getattr(auth_resp, "session", None)
    token_a = getattr(session, "access_token", None)
    user_a = getattr(auth_resp, "user", None)
    sub_a = _decode_sub(token_a) if token_a else None
    user_id_a = getattr(user_a, "id", None) or sub_a
    record("SIGN_IN", bool(token_a) and bool(user_id_a))

    # ------------------------------------------------------------------ 2
    print("\n[2] POST /api/reports/generate")
    gen_headers = {"Authorization": f"Bearer {token_a}"}
    gen_payload = {
        "title": f"Real E2E Pipeline Test {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
    }
    try:
        gen_resp = requests.post(
            f"{base}/api/reports/generate", json=gen_payload, headers=gen_headers, timeout=60
        )
    except Exception as exc:  # noqa: BLE001
        record("REPORT GENERATION", False, f"request error: {type(exc).__name__}: {exc}")
        return 1

    try:
        gen_body = gen_resp.json()
    except Exception:  # noqa: BLE001
        gen_body = {}

    report = gen_body.get("data", {}) if gen_body.get("success") else {}
    report_id = report.get("id")
    storage_path = report.get("storage_path")
    signed_url = report.get("signed_url")
    report_data = report.get("report_data") or {}

    gen_ok = gen_resp.status_code == 201 and bool(report_id)
    if not gen_ok:
        NOTES.append(f"generate status={gen_resp.status_code} body={json.dumps(gen_body)[:500]}")
    record("REPORT GENERATION", gen_ok, f"id={report_id}")

    if not gen_ok:
        print("[ERROR] Report generation failed; aborting before any destructive step.")
        return 1

    # ------------------------------------------------------------------ 3
    print("\n[3] Ownership-safe format + report_type + ownership")
    fmt_ok = (
        isinstance(storage_path, str)
        and storage_path == f"{user_id_a}/{report_id}.pdf"
        and "/" not in report_id
        and re.fullmatch(r"[0-9a-fA-F-]{36}", report_id) is not None
    )
    record("STORAGE_PATH_FORMAT", fmt_ok, f"storage_path={storage_path}")

    ownership_ok = (
        report.get("user_id") == user_id_a
        and report.get("report_type") == "pdf"
    )
    record("REPORT_OWNERSHIP_AND_TYPE", ownership_ok,
           f"user_id==sub: {report.get('user_id') == user_id_a}")

    # ------------------------------------------------------------------ 4
    print("\n[4] Scan snapshot in report_data (aggregates real persisted scans)")
    snapshot_ok = (
        isinstance(report_data, dict)
        and all(k in report_data for k in ("website_scan", "email_scan", "password_scan", "log_scan"))
    )
    if snapshot_ok:
        populated = [k for k in ("website_scan", "email_scan", "password_scan", "log_scan")
                     if report_data.get(k)]
        empty = [k for k in ("website_scan", "email_scan", "password_scan", "log_scan")
                 if not report_data.get(k)]
        NOTES.append(f"report_data sections populated: {populated}; empty: {empty}")

        # Cross-check against the REAL persisted latest scans for this user.
        for table, section, db_column, report_key in (
            ("website_scans", "website_scan", "target_url", "target"),
            ("email_scans", "email_scan", "subject", "subject"),
            ("password_scans", "password_scan", "password_length", "password_length"),
            ("log_scans", "log_scan", "event_count", "event_count"),
        ):
            try:
                rows = (
                    admin.table(table)
                    .select("*")
                    .eq("user_id", user_id_a)
                    .order("created_at", desc=True)
                    .limit(1)
                    .execute()
                ).data
            except Exception as exc:  # noqa: BLE001
                NOTES.append(f"admin read {table} failed: {type(exc).__name__}")
                continue
            latest = rows[0] if rows else None
            mapped = report_data.get(section)
            if latest is not None and mapped is not None:
                live_val = latest.get(db_column)
                mapped_val = mapped.get(report_key)
                if live_val != mapped_val:
                    snapshot_ok = False
                    NOTES.append(
                        f"{table}: live {db_column}={live_val!r} != report {section}.{report_key}={mapped_val!r}"
                    )
            elif latest is None and mapped is not None:
                snapshot_ok = False
                NOTES.append(f"{table}: no live row but report contains a section")
            elif latest is not None and mapped is None:
                snapshot_ok = False
                NOTES.append(f"{table}: live row exists but report section is None")
    record("REPORT_DATA_SNAPSHOT", snapshot_ok)

    # ------------------------------------------------------------------ 5
    print("\n[5] PDF creation + real Storage upload + signed URL retrieval")
    pdf_bytes = b""
    signed_ok = False
    try:
        resp = requests.get(signed_url, timeout=30)
        pdf_bytes = resp.content
        signed_ok = resp.status_code == 200 and _is_pdf(pdf_bytes)
        if not signed_ok:
            NOTES.append(
                f"signed URL fetch status={resp.status_code} ctype={resp.headers.get('content-type')}"
            )
    except Exception as exc:  # noqa: BLE001
        NOTES.append(f"signed URL fetch error: {type(exc).__name__}: {exc}")
    record("SIGNED URL", signed_ok, f"pdf_bytes={len(pdf_bytes)}")

    storage_upload_ok = False
    stored = b""
    try:
        stored = admin.storage.from_(bucket).download(storage_path)
        info = admin.storage.from_(bucket).info(storage_path)
        content_type = (
            info.get("content_type")
            or (info.get("metadata") or {}).get("mimetype")
            or ""
        )
        storage_upload_ok = _is_pdf(stored) and content_type == "application/pdf"
        if not storage_upload_ok:
            NOTES.append(
                f"storage object: pdf={_is_pdf(stored)} content_type={content_type!r}"
            )
    except Exception as exc:  # noqa: BLE001
        NOTES.append(f"admin storage download/info error: {type(exc).__name__}: {exc}")
    record("STORAGE UPLOAD", storage_upload_ok, f"path={storage_path}")

    # ReportLab must have produced a real PDF: prove it from the uploaded object
    # (falling back to the signed-URL fetch).
    pdf_created_ok = _is_pdf(stored) or signed_ok
    record("PDF CREATION", pdf_created_ok, f"pdf_bytes={len(stored)}")

    # ------------------------------------------------------------------ 6
    print("\n[6] Real public.reports insert")
    report_row = None
    insert_ok = False
    try:
        rows = admin.table("reports").select("*").eq("id", report_id).execute().data
        report_row = rows[0] if rows else None
        if report_row:
            insert_ok = (
                report_row.get("user_id") == user_id_a
                and report_row.get("report_type") == "pdf"
                and report_row.get("storage_path") == storage_path
                and isinstance(report_row.get("report_data"), dict)
                and bool(report_row.get("report_data"))
            )
            if not insert_ok:
                NOTES.append(
                    f"reports row mismatch: {json.dumps({k: report_row.get(k) for k in ('user_id','report_type','storage_path')})[:400]}"
                )
    except Exception as exc:  # noqa: BLE001
        NOTES.append(f"admin reports read error: {type(exc).__name__}: {exc}")
    record("REPORT DB INSERT", insert_ok, f"report_id={report_id}")

    # ------------------------------------------------------------------ 7
    print("\n[7] GET /api/reports (same JWT) returns the report + working signed URL")
    list_ok = False
    listed_signed_ok = False
    try:
        list_resp = requests.get(f"{base}/api/reports", headers=gen_headers, timeout=30)
        listed = list_resp.json().get("data", []) if list_resp.status_code == 200 else []
        listed_ids = [r.get("id") for r in listed]
        list_ok = list_resp.status_code == 200 and report_id in listed_ids
        listed_report = next((r for r in listed if r.get("id") == report_id), None)
        if listed_report and listed_report.get("signed_url"):
            lr = requests.get(listed_report["signed_url"], timeout=30)
            listed_signed_ok = lr.status_code == 200 and _is_pdf(lr.content)
            if not listed_signed_ok:
                NOTES.append(f"listed signed URL status={lr.status_code}")
    except Exception as exc:  # noqa: BLE001
        NOTES.append(f"list request error: {type(exc).__name__}: {exc}")
    record("GET /api/reports", list_ok, f"count={len(listed) if 'listed' in dir() else 'n/a'}")
    record("LISTED_SIGNED_URL_WORKS", listed_signed_ok)

    # ------------------------------------------------------------------ 8
    print("\n[8] Cross-user isolation with a REAL second user")
    isolation_ok = True
    second_user_id = None
    email_b = f"cs-e2e-{uuid.uuid4().hex[:12]}@example.com"
    pw_b = "E2e!" + uuid.uuid4().hex + "x"
    admin_auth_headers = {
        "apikey": secret_key,
        "Authorization": f"Bearer {secret_key}",
        "Content-Type": "application/json",
    }
    try:
        create_resp = requests.post(
            f"{supabase_url}/auth/v1/admin/users",
            headers=admin_auth_headers,
            json={"email": email_b, "password": pw_b, "email_confirm": True},
            timeout=30,
        )
        created = create_resp.json() if create_resp.status_code == 200 else {}
        second_user_id = created.get("id")
        if not second_user_id:
            isolation_ok = False
            NOTES.append(f"second user creation failed: {create_resp.status_code} {json.dumps(created)[:300]}")
    except Exception as exc:  # noqa: BLE001
        isolation_ok = False
        NOTES.append(f"second user creation error: {type(exc).__name__}: {exc}")

    if second_user_id:
        try:
            auth_b = client.auth.sign_in_with_password({"email": email_b, "password": pw_b})
            token_b = getattr(getattr(auth_b, "session", None), "access_token", None)
        except Exception as exc:  # noqa: BLE001
            token_b = None
            isolation_ok = False
            NOTES.append(f"second user sign-in error: {type(exc).__name__}: {exc}")

        if token_b:
            user_b_headers = {"Authorization": f"Bearer {token_b}"}
            anon_headers = {"apikey": anon_key, "Authorization": f"Bearer {token_b}"}

            try:
                lr_b = requests.get(f"{base}/api/reports", headers=user_b_headers, timeout=30)
                listed_b = lr_b.json().get("data", []) if lr_b.status_code == 200 else []
                listed_b_ids = [r.get("id") for r in listed_b]
                db_isolation = report_id not in listed_b_ids
                if not db_isolation:
                    isolation_ok = False
                    NOTES.append("user B can list report A via GET /api/reports")
            except Exception as exc:  # noqa: BLE001
                isolation_ok = False
                NOTES.append(f"user B list error: {type(exc).__name__}: {exc}")

            # Storage object must NOT be readable by user B without a signed URL.
            try:
                obj_url = f"{supabase_url}/storage/v1/object/authenticated/{bucket}/{storage_path}"
                r_obj = requests.get(obj_url, headers=anon_headers, timeout=30)
                obj_leaked = r_obj.status_code == 200 and _is_pdf(r_obj.content)
                if obj_leaked:
                    isolation_ok = False
                    NOTES.append(f"user B downloaded report A object directly (status {r_obj.status_code})")
                else:
                    NOTES.append(f"user B direct object fetch status={r_obj.status_code}")
            except Exception as exc:  # noqa: BLE001
                NOTES.append(f"user B object fetch error: {type(exc).__name__}: {exc}")

            # User B must not be able to issue a signed URL for report A's object.
            try:
                r_sign = requests.post(
                    f"{supabase_url}/storage/v1/object/sign/{bucket}/{storage_path}",
                    headers=anon_headers,
                    json={"expiresIn": 3600},
                    timeout=30,
                )
                sign_leaked = r_sign.status_code == 200 and r_sign.json().get("signedURL")
                if sign_leaked:
                    isolation_ok = False
                    NOTES.append("user B created a signed URL for report A's object")
                else:
                    NOTES.append(f"user B sign request status={r_sign.status_code}")
            except Exception as exc:  # noqa: BLE001
                NOTES.append(f"user B sign error: {type(exc).__name__}: {exc}")

            # User B must not be able to list report A's object.
            try:
                r_list = requests.post(
                    f"{supabase_url}/storage/v1/object/list/{bucket}",
                    headers=anon_headers,
                    json={"prefix": "", "limit": 1000, "offset": 0, "sortBy": {"column": "name", "order": "asc"}},
                    timeout=30,
                )
                if r_list.status_code == 200:
                    listed_objs = [o.get("name") for o in r_list.json()]
                    list_leaked = any(storage_path in (o or "") for o in listed_objs)
                    if list_leaked:
                        isolation_ok = False
                        NOTES.append("user B listed report A's object")
                    else:
                        NOTES.append(f"user B bucket list returned {len(listed_objs)} objects (report A absent)")
                else:
                    NOTES.append(f"user B bucket list status={r_list.status_code}")
            except Exception as exc:  # noqa: BLE001
                NOTES.append(f"user B list error: {type(exc).__name__}: {exc}")

    record("CROSS-USER ISOLATION", isolation_ok)

    # ------------------------------------------------------------------ 9
    print("\n[9] Live log_scans.risk_level constraint vs schema (schema.sql: plain TEXT, no CHECK)")
    # Probe candidate values through the service-role client. Every accepted row
    # is kept (with its id recorded) until the final cleanup step.
    constraint_probe_ids = []
    candidate_values = [
        "low", "medium", "high", "critical",
        "info", "warn", "severe", "suspicious", "none",
        "", "probe_invalid_value",
    ]
    allowed_values = []
    rejected_values = []
    for value in candidate_values:
        probe = {
            "user_id": user_id_a,
            "event_count": 0,
            "anomaly_count": 0,
            "findings": [],
            "risk_level": value,
            "model_version": "constraint-probe",
        }
        try:
            insert_resp = admin.table("log_scans").insert(probe).execute()
            probe_id = insert_resp.data[0]["id"] if insert_resp.data else None
            if probe_id:
                constraint_probe_ids.append(probe_id)
                allowed_values.append(value or "(empty)")
        except Exception as exc:  # noqa: BLE001
            rejected_values.append(value or "(empty)")
            if "violates check constraint" in str(exc).lower():
                NOTES.append(f"live log_scans.risk_level rejected {value or '(empty)'} (check constraint)")

    if rejected_values:
        schema_matches = False
        NOTES.append(
            "MISMATCH (reported separately): live log_scans.risk_level HAS a CHECK constraint "
            f"`log_scans_risk_level_check`; schema.sql declares plain TEXT with no CHECK. "
            f"Allowed by live: {allowed_values}; rejected: {rejected_values}."
        )
    else:
        schema_matches = True
        NOTES.append("live log_scans.risk_level has NO effective CHECK constraint (matches schema.sql plain TEXT).")
    record("LOG RISK-LEVEL SCHEMA CHECK", schema_matches)

    # ------------------------------------------------------------------ cleanup
    print("\n[10] Cleanup of ONLY this test's artifacts (after all verifications)")
    # Constraint probe rows.
    for probe_id in constraint_probe_ids:
        try:
            admin.table("log_scans").delete().eq("id", probe_id).execute()
            print(f"  [OK] removed constraint probe row {probe_id}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [WARN] probe row cleanup failed: {type(exc).__name__}: {exc}")
    # Synthetic second user (cascade removes any rows it owns).
    if second_user_id:
        try:
            del_resp = requests.delete(
                f"{supabase_url}/auth/v1/admin/users/{second_user_id}",
                headers=admin_auth_headers,
                timeout=30,
            )
            if del_resp.status_code in (200, 204):
                print(f"  [OK] removed synthetic second test user {second_user_id}")
            else:
                print(f"  [WARN] second user cleanup status={del_resp.status_code}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [WARN] second user cleanup error: {type(exc).__name__}: {exc}")

    # Sign the test user out (best effort).
    try:
        client.auth.sign_out()
    except Exception:  # noqa: BLE001
        pass

    # ------------------------------------------------------------------ summary
    print("\n" + "=" * 64)
    print("FINAL REPORT")
    print("=" * 64)
    for name in (
        "REPORT GENERATION",
        "PDF CREATION",
        "STORAGE UPLOAD",
        "REPORT DB INSERT",
        "SIGNED URL",
        "GET /api/reports",
        "CROSS-USER ISOLATION",
        "LOG RISK-LEVEL SCHEMA CHECK",
    ):
        status = "PASS" if RESULTS.get(name) else "FAIL"
        print(f"{name}: {status}")

    if NOTES:
        print("\nNotes:")
        for note in NOTES:
            print(f"  - {note}")

    overall = all(
        RESULTS.get(n)
        for n in (
            "REPORT GENERATION",
            "PDF CREATION",
            "STORAGE UPLOAD",
            "REPORT DB INSERT",
            "SIGNED URL",
            "GET /api/reports",
            "CROSS-USER ISOLATION",
            "LOG RISK-LEVEL SCHEMA CHECK",
        )
    )
    print(f"\nOVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())

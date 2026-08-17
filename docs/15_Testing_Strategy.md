# Testing Strategy

## Current Status
- The backend suite currently collects **898** tests (`python -m pytest --collect-only`).
- Key suites include: `test_sql_lab_redteam.py` (316), `test_sql_lab.py` (166),
  `test_sql_playground.py` (40), plus auth, scanner, email, password, logs,
  reports, dashboard, crypto, JWT, RLS scoping, and error-handling suites.
- Tests run fully offline: the Supabase client is replaced with a deterministic
  in-memory fake and JWT verification uses an in-test RSA key, so no network,
  database, or ML models are required.
- The frontend currently has no automated test framework installed.

## Objectives
- Verify functionality of every module.
- Validate API responses.
- Ensure ML predictions work correctly (once ML inference is implemented).
- Test database integration.
- Verify report generation.

## Testing Types
- Unit Testing
- Integration Testing
- API Testing
- UI Testing
- Security Testing
- Performance Testing

## Acceptance Criteria
- All APIs return expected responses.
- UI is responsive.
- Reports generate successfully.
- Authentication works securely.

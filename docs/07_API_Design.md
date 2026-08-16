# API Design

## Authentication
Handled by Supabase Auth, called directly from React:
- POST /auth/v1/signup
- POST /auth/v1/token?grant_type=password
- POST /auth/v1/logout
- GET /auth/v1/user

React holds the Supabase session and sends the access JWT to Flask as `Authorization: Bearer <JWT>`.

## Authorization
All Flask endpoints below require a valid Supabase Auth JWT. Flask verifies the JWT and reads the user ID from the token (sub claim = `auth.uid()`). Requests without a valid token return 401.

## Website Scanner
POST /api/scanner/website

## Email Detector
POST /api/email/analyze

## Password Analyzer
POST /api/password/analyze

## Log Analyzer
POST /api/logs/analyze

## Dashboard
GET /api/dashboard

Returns the authenticated user's aggregated security overview: metric cards
(security score, scans completed, threats detected, assets monitored), recent
scans, a synthesized activity feed, and a 12-day scan trend. All data is
derived from the user's own scan and report tables via user-scoped, RLS-preserving
reads. `user_id` always comes from the verified JWT; query parameters and the
request body are ignored.

## Reports
GET /api/reports
POST /api/reports/generate

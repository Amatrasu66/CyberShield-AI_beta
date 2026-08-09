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

## Reports
GET /api/reports
POST /api/reports/generate

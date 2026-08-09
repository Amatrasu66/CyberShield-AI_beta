# Database Design

## Database
Supabase (PostgreSQL)

## Authentication
- Supabase Auth manages the authentication user store in `auth.users`.
- No `public.users` table. Password hashes are never stored in the application database.
- Application user data lives in `public.profiles`, linked 1:1 to `auth.users.id`.
- Do not duplicate email in `profiles`; `auth.users.email` is the canonical authentication email.

## Application Tables
- profiles
- website_scans
- email_scans
- password_scans
- log_scans
- reports

## profiles
- `id uuid` PRIMARY KEY, references `auth.users.id` (1:1, no generated id)
- `full_name text`
- `role text` (Student / Faculty / Internship Evaluator, CHECK-constrained)
- `created_at timestamptz`
- `updated_at timestamptz`

## website_scans
- `id uuid` PRIMARY KEY
- `user_id uuid NOT NULL` FK -> `auth.users.id` (ON DELETE CASCADE)
- `target_url text NOT NULL`
- `status text` (pending / running / completed / failed)
- `security_score integer` (0-100, CHECK)
- `risk_level text` (low / medium / high / critical)
- `findings jsonb`
- `created_at timestamptz`

## email_scans
- `id uuid` PRIMARY KEY
- `user_id uuid NOT NULL` FK -> `auth.users.id` (ON DELETE CASCADE)
- `subject text`
- `sender_email text`
- `predicted_label text` (phishing / safe)
- `confidence numeric`
- `risk_level text`
- `indicators jsonb`
- `model_version text`
- `created_at timestamptz`
- Raw email content is not persisted by default; store findings/indicators only.

## password_scans
- `id uuid` PRIMARY KEY
- `user_id uuid NOT NULL` FK -> `auth.users.id` (ON DELETE CASCADE)
- `password_length integer`
- `entropy numeric`
- `strength_score integer` (0-100)
- `strength_label text`
- `has_upper boolean`
- `has_lower boolean`
- `has_number boolean`
- `has_symbol boolean`
- `breached boolean`
- `created_at timestamptz`
- Derived metrics only. Never store the analyzed password or its hash.

## log_scans
- `id uuid` PRIMARY KEY
- `user_id uuid NOT NULL` FK -> `auth.users.id` (ON DELETE CASCADE)
- `event_count integer`
- `anomaly_count integer`
- `findings jsonb`
- `risk_level text`
- `model_version text`
- `created_at timestamptz`
- Raw log content is not persisted by default; store findings/results only.

## reports
- `id uuid` PRIMARY KEY
- `user_id uuid NOT NULL` FK -> `auth.users.id` (ON DELETE CASCADE)
- `title text`
- `report_type text` (pdf)
- `storage_path text` (Supabase Storage object key)
- `report_data jsonb` (snapshot of scan summary at generation time)
- `created_at timestamptz`

## Relationships
- One user (`auth.users.id`) can own many scans and reports.
- `profiles.id` -> `auth.users.id` (1:1).
- All scan tables and reports reference the owning user via `user_id`.

## Row Level Security
- Enable RLS on all application tables.
- `profiles`: SELECT / UPDATE allowed only for `id = auth.uid()`.
- Scan tables and reports: SELECT / INSERT / UPDATE / DELETE only for `user_id = auth.uid()`.
- Normal user-scoped access preserves RLS; service-role credentials are server-only and reserved for elevated operations.

## Indexes
- `profiles.id` (PRIMARY KEY)
- `auth.users.email` is indexed by Supabase Auth.
- B-tree index on `user_id` for every scan table and `reports`.
- Composite `(user_id, created_at)` per scan table for recent-scan queries.

## Storage
- Generated PDFs use a private Supabase Storage bucket with signed access URLs.

## Never Stored
- Analyzed passwords or their hashes.
- Raw email content and raw log content (findings only).
- Password hashes (handled internally by Supabase Auth only).
- Secrets, service-role credentials, API keys.

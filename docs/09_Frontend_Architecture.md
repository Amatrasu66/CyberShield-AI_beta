# Frontend Architecture

Framework: React + TypeScript

## Main Pages
Routing is defined in `frontend/src/App.tsx`; every tool page is rendered inside
the authenticated app shell (`RequireAuth` + `AppShell`):
- Login / Register / Forgot Password (`AuthPage`) — `/login`, `/register`, `/forgot-password` (guest-only)
- Dashboard (`DashboardPage`) — `/dashboard`
- Website Scanner (`WebsiteScannerPage`) — `/website-scanner`
- Email Detector (`EmailDetectorPage`) — `/phishing-detector`
- Password Analyzer (`PasswordAnalyzerPage`) — `/password-analyzer`
- Log Analyzer (`LogAnalyzerPage`) — `/log-analyzer`
- SQL Playground (`SQLPlaygroundPage.tsx`) — `/sql-playground` (implemented)
- Cryptography Lab (`CryptographyLabPage.tsx`) — `/cryptography-lab` (implemented)
- Reports (`ReportsPage`) — `/reports`
- Tutorials Index (`TutorialsIndexPage`) — `/tutorials`
- Tutorial Area (`TutorialAreaPage`) — `/tutorials/:area`
- Tutorial Lesson (`TutorialLessonPage`) — `/tutorials/:area/:lesson`
- Profile / Settings (Workspace pages) — `/profile`, `/settings`
- NotFound — catch-all

## Client Libraries
- `src/lib/cryptoEngine.ts` — browser Web Crypto engine (SHA-256/SHA-512, AES-256-GCM, PBKDF2-HMAC-SHA256, HMAC-SHA256, base64/hex, secure random). Runs client-side; sensitive crypto material is never sent to the backend.
- `src/lib/cryptoEngine.selftest.ts` — in-repo selftest for the crypto engine.

## Data Access
- `src/services/apiClient.ts` attaches the Supabase session Bearer token to API
  calls and is used by the Dashboard, Website Scanner, Email Detector, Password
  Analyzer, Log Analyzer, SQL Playground, and Reports pages.
- The Cryptography Lab is browser-first: `CryptographyLabPage.tsx` and
  `cryptoEngine.ts` perform hashing, encoding, AES-256-GCM, HMAC, and random
  generation entirely in the browser via the Web Crypto API. It does **not** use
  `apiClient` and does not call `/api/crypto/*`; plaintext, passphrases, and
  keys never leave the page.

## Tutorials
- Documentation-only, frontend-only education layer. Rendered from structured typed
  data — no markdown renderer, no backend lesson endpoints. Fully documented in
  `docs/19_Tutorials_Architecture.md`.
- `src/types/tutorials.ts` — content model (`TutorialArea`, `TutorialLesson`,
  `text`/`list`/`callout`/`example` section union, `TutorialStatus = 'ready' | 'planned'`).
- `src/data/tutorialContent.ts` — `tutorialAreas` (9 `ready` areas × 4 lessons, plus the
  `ai-ml` area as `planned` with 0 lessons).
- `src/pages/tutorials/` — `TutorialsIndexPage`, `TutorialAreaPage`, `TutorialLessonPage`
  (routes in `App.tsx` inside the protected console group).
- `src/components/tutorials/` — `AreaCard`, `LessonSectionView`, `LessonPager`,
  `TutorialNotFound`.
- Navigation: "Tutorials" sidebar entry in `src/data/mockData.ts`; pages reuse
  `PageHeader`, `Card`, `Badge`, `.eyebrow`, and token classes only. Uses no `apiClient`.

## State Management
Prefer Context API (`AuthProvider`) initially.
Use reusable components throughout.
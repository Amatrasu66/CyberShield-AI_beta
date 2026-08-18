import { BarChart3, Brain, Bug, FileText, KeyRound, LayoutDashboard, MailWarning, ScanSearch, ShieldCheck, UserRound } from 'lucide-react';
import type { TutorialArea } from '../types/tutorials';

export const tutorialAreas: readonly TutorialArea[] = [
  {
    slug: 'website-scanner',
    title: 'Website Scanner',
    eyebrow: 'Attack surface',
    description: 'Inspect a public URL for HTTPS posture, TLS certificate validity, security headers, cookie flags and information disclosure signals.',
    icon: ScanSearch,
    toolLabel: 'Website Scanner',
    toolPath: '/website-scanner',
    status: 'ready',
    lessons: [
      {
        id: 'what-it-does',
        title: 'What the Website Scanner does',
        summary: 'A passive, non-destructive assessment of a public site — what it inspects and what it deliberately does not do.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'The Website Scanner performs a passive, non-destructive assessment of a public website. Give it a URL and it fetches only the response headers, checks the site\u2019s configuration signals, and returns a weighted score from 0\u2013100 with a letter grade. The result card and the detailed findings list tell you which checks passed, which failed, and what to fix.',
          },
          {
            kind: 'list',
            title: 'What it checks',
            items: [
              'HTTPS enforcement and TLS certificate validity (including days until expiry).',
              'Six security headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy.',
              'Cookie attributes: Secure, HttpOnly and SameSite.',
              'CORS posture and information disclosure (Server / X-Powered-By headers).',
              'Warning-level notes for unusual HTTP status codes and oversized response bodies.',
            ],
          },
          {
            kind: 'text',
            title: 'What it does NOT do',
            body: 'It is not a penetration tester. It performs no exploitation, no fuzzing, no credential testing and no authentication bypass. It only surfaces configuration weaknesses that a defender can fix, which is why it is safe to use on your own sites.',
          },
          {
            kind: 'callout',
            title: 'Scan responsibly',
            tone: 'warning',
            body: 'Only scan websites you own or have explicit permission to test. The backend refuses targets that resolve to private, loopback, link-local or reserved addresses so the tool cannot be pointed at internal networks.',
          },
        ],
        related: [
          { label: 'Try the scanner', to: '/website-scanner' },
          { label: 'Tutorial: Cryptography Lab', to: '/tutorials/cryptography-lab' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'What to provide and how to run a scan',
        summary: 'Valid target URLs, the 2048-character limit, and the scan flow in the page.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'What you provide',
            body: 'A single URL that starts with http:// or https:// and includes a hostname. URLs that embed credentials are rejected, and the target is capped at 2048 characters. If the hostname resolves to a private or loopback address, the scan is refused with a validation error.',
          },
          {
            kind: 'list',
            title: 'Steps in the page',
            items: [
              'Open /website-scanner.',
              'Type the target URL into the "Target URL" field.',
              'Click "Start security scan".',
              'Read the score, grade, risk and summary in the result card.',
              'Expand "Detailed findings" to review every check, its status, and its recommendation.',
            ],
          },
          {
            kind: 'text',
            title: 'Unreachable targets',
            body: 'If the target cannot be reached (timeout, TLS failure, too many redirects, or a connection error), the result shows 0/100 with grade F, an error message, and — unlike completed scans — the failed attempt is not stored in your scan history.',
          },
          {
            kind: 'text',
            title: 'Fetch behavior',
            body: 'The request uses a short timeout (10 seconds by default), follows at most 5 redirects, and never downloads the response body. If the target advertises a body larger than the 512 KB scan ceiling, you get a size warning instead of a download.',
          },
        ],
        related: [
          { label: 'Reading the results', to: '/tutorials/website-scanner/reading-results' },
          { label: 'Tutorial: Dashboard', to: '/tutorials/dashboard' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading the results',
        summary: 'How the checks, statuses, score, grade and risk level fit together — and how to act on them.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'Score and grade',
            body: 'The score is the percentage of pass/fail checks that passed; warning and info items do not count as either. Grades follow a fixed ladder: A for 90\u2013100, B for 75\u201389, C for 60\u201374, D for 40\u201359, and F below 40. The risk level is derived from the score: 75+ is low, 60\u201374 medium, 40\u201359 high, and below 40 critical.',
          },
          {
            kind: 'list',
            title: 'Check statuses',
            items: [
              'passed — the check is configured correctly and counts toward your score.',
              'failed — the check is missing or misconfigured and lowers your score.',
              'warning — a concern worth review, such as cookies missing Secure/HttpOnly, a wildcard CORS header, disclosure headers, or an unusual HTTP status.',
              'info — informational only; for example HSTS only applies over HTTPS, so it is \u201cinfo\u201d on an HTTP-only site.',
            ],
          },
          {
            kind: 'text',
            title: 'How to act',
            body: 'Treat every failed check as a configuration task rather than a vulnerability verdict. A failed Content-Security-Policy check means the header is absent — a concrete improvement you can deploy. Warnings tell you what to investigate next.',
          },
          {
            kind: 'example',
            title: 'Illustrative result',
            inputLabel: 'Target URL',
            input: 'https://example.com',
            outputLabel: 'Result shape',
            output: 'Score 84/100 \u00b7 Grade B \u00b7 Risk low\nSummary: 6 passed, 2 failed, 2 warning(s) out of 10 checks.',
            detail: 'Illustrative only — the real values depend on the live response. The scanner counts passed and failed checks, ignores warnings for the score, and maps the result to a grade and risk level.',
          },
          {
            kind: 'callout',
            title: 'Common mistakes',
            tone: 'warning',
            body: 'Trying to scan localhost, 127.0.0.1 or LAN addresses — those are refused on purpose (the SSRF guard, not a bug). Reading the grade as an absolute \u201chackable / not hackable\u201d verdict — a high score only means the checked signals look good. Treating info statuses as failures — they carry no score penalty.',
          },
        ],
        related: [
          { label: 'How it works', to: '/tutorials/website-scanner/under-the-hood' },
          { label: 'Tutorial: Reports', to: '/tutorials/reports' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How it works behind the scenes',
        summary: 'The request pipeline, the check list, the score math, and the security concepts the scanner demonstrates.',
        readMinutes: 5,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'The backend validates your URL, rejects private/reserved targets, then makes a requests.Session GET with verify=True (TLS validated against the system trust store), stream=True (headers only, no body), a redirect cap and a timeout. It parses the response headers, examines every Set-Cookie header, and runs the fixed check list. Only a completed, reachable scan is persisted to your website_scans table through a user-scoped client.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'TLS — HTTPS enforcement and certificate validity are the transport layer of trust.',
              'Security headers — CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy reduce browser-side attack surface.',
              'Cookie flags — Secure, HttpOnly and SameSite limit session-hijacking and script access.',
              'CORS — controls which origins may read cross-origin responses.',
              'Information disclosure — Server and X-Powered-By leak the technology stack to attackers.',
              'SSRF guard — private and reserved addresses are refused so the scanner cannot be abused as a proxy.',
            ],
          },
          {
            kind: 'text',
            title: 'Privilege and data boundaries',
            body: 'Your user id always comes from the verified JWT, never from the request body. The persisted row is scoped to you by row-level security, and only the target URL, numeric score, risk level and findings are stored — nothing else.',
          },
          {
            kind: 'callout',
            title: 'Limitations',
            tone: 'primary',
            body: 'The scanner is passive and configuration-focused. It cannot detect application-level bugs such as broken access control or business-logic flaws, does not run JavaScript or crawl the site, and cannot prove the absence of vulnerabilities. A clean check list is a checkpoint, not a full security audit.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Scan only assets you own or were explicitly authorized to test. Treat results as advisory checkpoints for defenders, not reconnaissance against third parties. When in doubt, practice against a staging site you control.',
          },
        ],
        related: [
          { label: 'Tutorial: Email / Phishing Detector', to: '/tutorials/phishing-detector' },
          { label: 'Try the scanner', to: '/website-scanner' },
        ],
      },
    ],
  },
  {
    slug: 'phishing-detector',
    title: 'Phishing Email Detector',
    eyebrow: 'Email intelligence',
    description: 'Analyze message content for urgency language, credential requests, generic greetings and suspicious links using deterministic heuristics.',
    icon: MailWarning,
    toolLabel: 'Email / Phishing Detector',
    toolPath: '/phishing-detector',
    status: 'ready',
    lessons: [
      {
        id: 'what-it-does',
        title: 'What the detector does',
        summary: 'The pattern set it flags, how it classifies messages, and why it is rule-based — not AI — today.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'The detector analyzes the text of an email and flags patterns known from real phishing: urgency and pressure language, requests for credentials or payment details, non-personalized greetings, spam-style calls to action, embedded links, uncommon top-level domains, and punctuation or capitalization tells. It returns a list of indicators plus an overall risk verdict.',
          },
          {
            kind: 'list',
            title: 'When to use it',
            items: [
              'Checking a suspicious email you received — after removing any sensitive parts.',
              'Teaching what phishing indicators look like with crafted examples.',
              'Learning how deterministic heuristics differ from a trained model.',
            ],
          },
          {
            kind: 'callout',
            title: 'Rule-based today',
            tone: 'primary',
            body: 'The current analysis is fully rule-based heuristics. The app/ml PhishingDetectorModel is a placeholder and does not run, so no AI claim should be attached to this tool yet.',
          },
          {
            kind: 'callout',
            title: 'Never paste real secrets',
            tone: 'danger',
            body: 'Raw email text is never persisted or logged, but this is a demo tool. Do not enter real credentials or messages you could not afford to show in a classroom.',
          },
        ],
        related: [
          { label: 'Try the detector', to: '/phishing-detector' },
          { label: 'Tutorial: Password Analyzer', to: '/tutorials/password-analyzer' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'What to provide and how to analyze',
        summary: 'Pasted text or a PDF upload, the size limits, and the analysis flow in the page.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'What you provide',
            body: 'You can paste the message text directly or upload a PDF of the email. Pasted content is capped at 50 KB. PDFs are capped at 1 MB and must contain a text layer — text is extracted with pypdf, no OCR, so image-only and scanned PDFs are rejected with a clear message.',
          },
          {
            kind: 'list',
            title: 'Steps in the page',
            items: [
              'Open /phishing-detector.',
              'Switch between the "text" and "PDF" input modes.',
              'Paste the message or choose the file.',
              'Run the analysis.',
              'Review the verdict (safe / suspicious / phishing), the score bar, the confidence value, the summary, and each indicator with its severity and evidence.',
            ],
          },
          {
            kind: 'text',
            title: 'The verdict vocabulary',
            body: 'safe means low risk with no significant indicators; suspicious means elevated and worth a careful manual review; phishing means multiple or strong indicators are present. The is_phishing flag is true only for the phishing level.',
          },
          {
            kind: 'callout',
            title: 'Confidence is score-derived',
            tone: 'primary',
            body: 'The confidence value is a deterministic function of the risk score (min of 0.95 and 0.5 + score/200) — it is not a model probability and should not be read as a measure of attacker certainty.',
          },
        ],
        related: [
          { label: 'Reading the results', to: '/tutorials/phishing-detector/reading-results' },
          { label: 'Tutorial: Log Analyzer', to: '/tutorials/log-analyzer' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading the results',
        summary: 'Indicators, severity, score, risk level and confidence — plus a verified worked example.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'Indicators',
            body: 'Each check is reported as an indicator with a severity (High, Medium or Low) and the evidence found. High indicators matter most: urgency language, credential requests, and suspicious link domains. Medium severity covers spam-style calls to action, link density (3+ links), and excessive capitalization. Low covers generic greetings and excessive punctuation.',
          },
          {
            kind: 'text',
            title: 'Score and risk level',
            body: 'Scores run from 0\u2013100, starting at a base of 10 and adding 30 per High, 20 per Medium and 10 per Low indicator. The risk level is phishing at 70+, suspicious at 40\u201369, and safe below 40.',
          },
          {
            kind: 'example',
            title: 'Worked example',
            inputLabel: 'Pasted message (abridged)',
            input: 'Subject: Your account has been suspended\nFrom: support@secure-verify.tk\nDear customer, verify your password immediately or your account will be deactivated within 24 hours. Click here now: http://example.com/login!!',
            outputLabel: 'Result (verified output)',
            output: 'Risk 100/100 \u00b7 Level phishing \u00b7 Confidence 0.95 \u00b7 is_phishing true\nIndicators: Urgency language (High), Credential request (High),\nGeneric greeting (Low), Spam-style call to action (Medium),\nEmbedded links (Low), Excessive punctuation (Low)\nWord count 27 \u00b7 Link count 1',
            detail: 'This sample was run through the actual analyzer service to produce these values. The .tk domain is on the suspicious-TLD list, and the message hits urgency, credential, greeting, CTA and punctuation checks.',
          },
          {
            kind: 'callout',
            title: 'Common mistakes',
            tone: 'warning',
            body: 'Reading a \u201csafe\u201d verdict as a guarantee — the tool only sees the content you paste and does not inspect email headers (SPF, DKIM, DMARC) or the real sender server. Pasting production email content — use sanitized samples. Uploading a scanned image PDF and expecting OCR — image-only PDFs are rejected.',
          },
        ],
        related: [
          { label: 'How it works', to: '/tutorials/phishing-detector/under-the-hood' },
          { label: 'Tutorial: Email / Phishing Detector', to: '/tutorials/phishing-detector' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How it works behind the scenes',
        summary: 'The heuristic pipeline, why raw content is never stored, and the concepts the detector teaches.',
        readMinutes: 5,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'The service lowercases the text, counts words and URLs, and runs the fixed heuristic set: urgency words, credential words, generic greetings, spam actions, suspicious TLDs, punctuation and capitalization. Each triggered check becomes an indicator with a severity, and the sum drives the score, risk level and confidence. Only a summary row — subject, sender, predicted label, confidence, risk level and indicators — is persisted to email_scans. Raw email content is never stored or logged.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'Social engineering — attackers weaponize urgency, authority and fear.',
              'Credential harvesting — requests for passwords, bank or card details are a classic tell.',
              'Domain abuse — inexpensive top-level domains such as .tk, .ml, .ga, .cf, .gq, .xyz, .top and .work are flagged.',
              'Link inspection — counting and checking embedded links.',
              'Data minimization — the service persists findings, never the message itself.',
            ],
          },
          {
            kind: 'text',
            title: 'Limitations',
            body: 'There is no header analysis (SPF/DKIM/DMARC) and no sender-reputation lookup. The patterns are English-focused heuristics, so sophisticated spear-phishing that avoids stock phrases can pass. PDF input requires a real text layer. And because the analyzer is not model-backed, it will not improve with more data.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Use the detector on messages you received or on sample content you crafted for training. Strip real names, addresses and credentials first. It exists to raise awareness — never to collect or target anyone\u2019s real messages.',
          },
        ],
        related: [
          { label: 'Tutorial: Log Analyzer', to: '/tutorials/log-analyzer' },
          { label: 'Try the detector', to: '/phishing-detector' },
        ],
      },
    ],
  },
  {
    slug: 'password-analyzer',
    title: 'Password Analyzer',
    eyebrow: 'Credential hygiene',
    description: 'Measure password strength from length, character classes, pool-based entropy and inline common-password signals.',
    icon: KeyRound,
    toolLabel: 'Password Analyzer',
    toolPath: '/password-analyzer',
    status: 'ready',
    lessons: [
      {
        id: 'what-it-does',
        title: 'What the analyzer measures',
        summary: 'Entropy, crack-time category, common-password detection and the strength score derivation.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'The analyzer computes the password length and character classes, estimates pool-based entropy in bits, categorizes an approximate crack time, and flags whether the password matches an inline set of common weak passwords. It then derives a 0\u2013100 strength score and label, prioritized recommendations, structured weaknesses, a score breakdown, and a security checklist.',
          },
          {
            kind: 'list',
            title: 'Output sections',
            items: [
              'Strength score 0\u2013100 and a label: Weak, Fair, Good or Strong.',
              'Prioritized recommendations and structured weaknesses with severity.',
              'A score breakdown across length, variety, entropy, exposure and patterns.',
              'An entropy estimate and crack-time category for context.',
              'A security checklist with passed, failed and advisory items.',
            ],
          },
          {
            kind: 'callout',
            title: 'No real breach dataset',
            tone: 'warning',
            body: 'Common-password detection uses an inline set baked into the service, not a bundled password-file dataset. The datasets/passwords folder is a placeholder and is never loaded by the service, so \u201ccommon list\u201d only means this built-in list.',
          },
          {
            kind: 'callout',
            title: 'Never analyze a real password',
            tone: 'danger',
            body: 'Never run production passwords through this tool. Neither the plaintext nor any hash of it is stored, but it is a demo — use invented classroom inputs only.',
          },
        ],
        related: [
          { label: 'Try the analyzer', to: '/password-analyzer' },
          { label: 'Tutorial: Authentication & account', to: '/tutorials/authentication' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'How to use the analyzer and generator',
        summary: 'What to provide, how to run an analysis, and how the passphrase and random generators work.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'What you provide',
            body: 'To analyze, enter any password string (capped at 4096 characters). To generate, choose a type: a passphrase of 4\u20136 words (with a configurable delimiter, default "-") or a random password of 8\u201364 characters (default 20).',
          },
          {
            kind: 'list',
            title: 'Steps in the page',
            items: [
              'Open /password-analyzer.',
              'Type a demo password into the analyzer field (use the eye toggle to show or hide it).',
              'Read the score, label, weaknesses, recommendations, breakdown and checklist.',
              'Optionally generate a passphrase or random password and copy it.',
              'Compare an analyzed password against a generated one to see the difference.',
            ],
          },
          {
            kind: 'text',
            title: 'Generator security',
            body: 'Both generators use secrets.SystemRandom, a cryptographically secure random source. The random charset deliberately excludes ambiguous characters such as l, 1, I, O and 0. The passphrase wordlist is curated and every value is drawn with a CSPRNG, so outputs are unpredictable.',
          },
          {
            kind: 'callout',
            title: 'Treat generated passwords with respect',
            tone: 'warning',
            body: 'A generated value is real credential material. Keep it in a password manager and only use it on accounts you may access with it — do not paste it somewhere public.',
          },
        ],
        related: [
          { label: 'Reading the results', to: '/tutorials/password-analyzer/reading-results' },
          { label: 'Tutorial: Reports', to: '/tutorials/reports' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading the results',
        summary: 'How the score, labels, entropy, crack time and checklist are derived — with verified worked examples.',
        readMinutes: 5,
        sections: [
          {
            kind: 'text',
            title: 'Score and label',
            body: 'The score starts at 0 and accumulates length points (up to 30), character-variety points (up to 30), an entropy bonus (up to 25) and a length-plus-variety bonus (10). Penalties apply for short passwords, common-list matches (\u221230), sequential characters and repeated runs. Labels: Strong at 85+, Good at 70\u201384, Fair at 40\u201369, Weak below 40.',
          },
          {
            kind: 'text',
            title: 'Entropy and crack time',
            body: 'Pool-based entropy is length \u00d7 log\u2082(pool size), where the pool comes from the character classes present (26 lowercase, 26 uppercase, 10 digits, 33 special characters). The crack-time category assumes an idealized offline attacker at 10 billion guesses per second and runs from "instantly" up to "centuries". It is an educational estimate, not a real-world guarantee.',
          },
          {
            kind: 'text',
            title: 'Checklist semantics',
            body: 'Objective conditions are marked passed or failed. Advisor-only guidance — use a unique password, use a password manager, enable MFA — cannot be verified from the password alone, so it is always marked "advisory", never passed. A failed advisory is still good advice.',
          },
          {
            kind: 'example',
            title: 'Worked example: weak password',
            inputLabel: 'Password',
            input: 'password123',
            outputLabel: 'Result (verified output)',
            output: 'Length 11 \u00b7 2 classes (lowercase, digits)\nEntropy 56.87 bits \u00b7 Crack time: months\nin_common_list: false \u00b7 Score 31/100 \u00b7 Strength: Weak\nWeaknesses include: dictionary word, sequential pattern',
            detail: 'Verified by running the actual analyzer service. Even though "password123" is not in the inline common list, it still scores Weak because it contains a dictionary word and a sequential pattern, and it never appears "breached" in this tool\u2019s vocabulary without a positive common-list match.',
          },
          {
            kind: 'example',
            title: 'Worked example: strong password',
            inputLabel: 'Password',
            input: 'Tr0ub4dour&9!x',
            outputLabel: 'Result (verified output)',
            output: 'Length 14 \u00b7 4 classes\nEntropy 91.98 bits \u00b7 Crack time: centuries\nin_common_list: false \u00b7 Score 86/100 \u00b7 Strength: Strong',
            detail: 'Verified by running the actual analyzer service. Four character classes, long length and high entropy push the score to Strong.',
          },
          {
            kind: 'callout',
            title: 'Surprising but by design',
            tone: 'warning',
            body: 'The scorer heavily rewards character variety. A very long lowercase passphrase (for example, "correcthorsebatterystaple") can score "Fair" even though its entropy is enormous, because it only uses one character class. The score is a rule-based heuristic — it is not the same as real-world cracking resistance.',
          },
        ],
        related: [
          { label: 'How it works', to: '/tutorials/password-analyzer/under-the-hood' },
          { label: 'Tutorial: Authentication & account', to: '/tutorials/authentication' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How it works behind the scenes',
        summary: 'The deterministic scoring internals, what is persisted, and the security concepts it teaches.',
        readMinutes: 5,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'The service computes the length and character classes, estimates pool entropy, detects weaknesses (too short, common list, dictionary words, sequential and keyboard patterns, repeated characters or substrings, years, dates, phone numbers, and simple substitutions), then builds the score breakdown and checklist. It persists only derived metrics — password_length, entropy, strength_score, label, character flags and the breached flag — to password_scans. The plaintext password and any hash of it are never stored.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'Entropy — a measure of unpredictability in bits; length beats complexity.',
              'Character classes — variety expands the search pool, but length still dominates.',
              'CSPRNG vs weak randomness — generation uses the operating system\u2019s secure entropy, never Math.random().',
              'Breached-password mindset — never reuse credentials that have appeared in public breach lists.',
              'MFA — a strong password is one layer; multi-factor authentication adds a second.',
            ],
          },
          {
            kind: 'callout',
            title: 'Limitations',
            tone: 'primary',
            body: 'There is no internet lookup for anything — the common list is a small inline set. The crack-time is a rough classroom estimate. Scores are deterministic rules, not a model. Passphrase-level scoring can underrate long lowercase passphrases as described in the results lesson.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Use invented passwords or the generator here. Never submit a credential you actually use; that habit is exactly what this tool is meant to discourage. Enable MFA and unique passwords independently of this lab.',
          },
        ],
        related: [
          { label: 'Tutorial: Cryptography Lab', to: '/tutorials/cryptography-lab' },
          { label: 'Try the analyzer', to: '/password-analyzer' },
        ],
      },
    ],
  },
  {
    slug: 'log-analyzer',
    title: 'Log Analyzer',
    eyebrow: 'Threat telemetry',
    description: 'Parse access-log style lines into IP, method and status breakdowns, anomalies, and a threat score.',
    icon: BarChart3,
    toolLabel: 'Log Analyzer',
    toolPath: '/log-analyzer',
    status: 'ready',
    lessons: [
      {
        id: 'what-it-does',
        title: 'What the analyzer does',
        summary: 'How access-log lines are parsed, broken down and scored — and why it is rule-based today.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'Paste access-log style content and the analyzer parses each line, tallies status codes and top source IPs, and hunts for anomalies such as repeated failed logins, SQL injection attempts, path traversal, XSS probes and known scanning user agents. It returns totals, an anomaly list, a threat score and a severity.',
          },
          {
            kind: 'list',
            title: 'What it produces',
            items: [
              'Total, parsed and skipped line counts.',
              'A status-code distribution and unique-IP count.',
              'Top source IPs (up to five).',
              'An anomaly list with line number, type, severity and evidence.',
              'A 0\u2013100 threat score and severity: low, medium or high.',
            ],
          },
          {
            kind: 'callout',
            title: 'Rule-based today',
            tone: 'primary',
            body: 'Analysis is deterministic rules — there is no trained model yet. The app/ml LogAnalyzerModel is a placeholder and does not run, so do not describe this tool as machine-learning powered.',
          },
          {
            kind: 'callout',
            title: 'Raw content is never stored',
            tone: 'success',
            body: 'The service persists only derived artifacts (counts, findings, severity) to log_scans. The raw log lines themselves are never written or logged.',
          },
        ],
        related: [
          { label: 'Try the log analyzer', to: '/log-analyzer' },
          { label: 'Tutorial: Dashboard', to: '/tutorials/dashboard' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'What to provide and how to analyze',
        summary: 'Acceptable log formats, the 500 KB limit, and the analysis flow.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'What you provide',
            body: 'Access-log text in Apache combined or common log format. Content is capped at 500 KB. The format selector offers "Auto" and "Apache Combined"; lines that do not match the combined/common pattern are counted as skipped and do not feed the stats or anomaly checks.',
          },
          {
            kind: 'list',
            title: 'Steps in the page',
            items: [
              'Open /log-analyzer.',
              'Paste or type your log lines.',
              'Choose Auto or Apache Combined for the format.',
              'Run the analysis.',
              'Review the totals, status distribution, top sources, and the anomaly list with threat score and severity.',
            ],
          },
          {
            kind: 'text',
            title: 'Parsing behavior',
            body: 'Each non-empty line is matched against the combined-log regular expression (source IP, timestamp, request line with method/path/protocol, 3-digit status, and size). Anything else is skipped. All counts — parsed, skipped, anomalies — reflect only what the parser recognized.',
          },
        ],
        related: [
          { label: 'Reading the results', to: '/tutorials/log-analyzer/reading-results' },
          { label: 'Tutorial: SQL Playground', to: '/tutorials/sql-playground' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading the results',
        summary: 'Totals, status and IP breakdowns, anomaly types, and the threat score — with a verified worked example.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'Totals and breakdown',
            body: 'total_lines is the count of non-empty lines; parsed_lines is how many matched the log format; skipped_lines is the difference. The stats section shows a status-code histogram, unique IPs, and the top five sources by request count.',
          },
          {
            kind: 'text',
            title: 'Anomaly types',
            body: 'failed_authentication (401/403, High) and server_error (5xx, Medium) flag status patterns. sql_injection_attempt (High) matches SQL metacharacters in the URL-decoded path; path_traversal_attempt (High) matches ../ and encoded variants; xss_attempt (Medium) matches script/onerror/javascript: patterns; suspicious_user_agent (Medium) matches tools such as sqlmap, nikto, nessus, nmap, curl, wget, python-requests and zgrab. A brute_force_pattern (High) is reported when one IP has 3 or more failed logins. At most 200 anomalies are returned.',
          },
          {
            kind: 'text',
            title: 'Threat score and severity',
            body: 'The threat score sums weights (High 3, Medium 2, Low 1), multiplies by 4, and caps at 100. Severity is low below 30, medium from 30\u201359, and high at 60+.',
          },
          {
            kind: 'example',
            title: 'Worked example',
            inputLabel: 'Log excerpt (3 of 7 lines)',
            input: '203.0.113.7 - - [10/May/2026:12:00:02 +0000] "POST /login HTTP/1.1" 401 512\n198.51.100.9 - - [10/May/2026:12:00:05 +0000] "GET /products?id=1%20UNION%20SELECT HTTP/1.1" 200 2048\n198.51.100.9 - - [10/May/2026:12:00:06 +0000] "GET /admin/../etc/passwd HTTP/1.1" 200 4096',
            outputLabel: 'Result (verified output)',
            output: 'Total 7 lines \u00b7 Parsed 6 \u00b7 Skipped 1\nStatus: {200: 3, 401: 3} \u00b7 Unique IPs: 3\nThreat score 72/100 \u00b7 Severity: high \u00b7 Anomalies: 6\nFailed auth (High) \u00d73, SQL injection attempt (High),\nPath traversal attempt (High), Brute-force pattern (High)',
            detail: 'Verified by running the actual log analyzer on this sample. Note the URL-encoded UNION payload in the /products request — the analyzer URL-decodes paths before checking, so "%20UNION%20SELECT" is still caught.',
          },
          {
            kind: 'callout',
            title: 'Common mistakes',
            tone: 'warning',
            body: 'Feeding JSON or non-access logs — they get skipped, so parsed_lines stays low and the analysis is meaningless. Pasting production logs that still contain personal data — sanitize first. Reading the threat score as a percentage accuracy — it is a weighted anomaly indicator, not a judgment.',
          },
        ],
        related: [
          { label: 'How it works', to: '/tutorials/log-analyzer/under-the-hood' },
          { label: 'Tutorial: Website Scanner', to: '/tutorials/website-scanner' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How it works behind the scenes',
        summary: 'The parsing pipeline, the anomaly rules, persistence, and the security concepts involved.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'The service reads the content line by line, matches the combined log regular expression, and URL-decodes each request path before applying the pattern checks so encoded payloads are still caught. Aggregated brute-force patterns are added per IP, the anomaly list is trimmed to a cap, and the weighted threat score is computed. Only a summary row — event count, anomaly count, findings and severity — is written to log_scans through your user-scoped client.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'Access-log anatomy — the combined-log format separates IP, timestamp, request and status.',
              'URL encoding — attackers encode payloads to disguise them; decoding before matching closes that gap.',
              'Common attack signatures — SQLi metacharacters, traversal, XSS probes and credential-stuffing patterns.',
              'Scanning agents — automated tools advertise themselves in the User-Agent header.',
              'Log minimization — persist findings, not raw traffic.',
            ],
          },
          {
            kind: 'callout',
            title: 'Limitations',
            tone: 'primary',
            body: 'Only Apache combined/common format is parsed. Anomalies are fixed regex heuristics, not ML inference, and they cannot infer intent — a 200 response with "UNION" in the URL is flagged as an attempt, not proof of success. False positives are possible.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Analyze logs you own or that were shared with you for analysis, and only after removing personal data. Use the tool to learn what server-access logs reveal about attacker activity — not to target or expose anyone.',
          },
        ],
        related: [
          { label: 'Tutorial: SQL Playground', to: '/tutorials/sql-playground' },
          { label: 'Try the log analyzer', to: '/log-analyzer' },
        ],
      },
    ],
  },
  {
    slug: 'reports',
    title: 'Reports',
    eyebrow: 'Audit artifacts',
    description: 'Combine your saved scan results into a PDF audit report stored privately and delivered via signed URLs.',
    icon: FileText,
    toolLabel: 'Reports',
    toolPath: '/reports',
    status: 'ready',
    lessons: [
      {
        id: 'what-it-does',
        title: 'What reports do',
        summary: 'The PDF pipeline, the private storage model, and why a report can only cover your own scans.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'A report is a PDF audit document built from your saved scan history. Generating one reads your most recent completed scan from each of the four scan tables (website, email, password and log), assembles a JSON-safe snapshot, renders a PDF in memory with ReportLab, and uploads it to a private storage bucket.',
          },
          {
            kind: 'text',
            title: 'Access model',
            body: 'Report objects are namespaced under your user (user_id/report_id.pdf) inside a private bucket. They are only ever opened through freshly signed URLs — there is no public URL path at all, and signed URLs expire (by default after one hour).',
          },
          {
            kind: 'callout',
            title: 'Only your own data',
            tone: 'warning',
            body: 'A report can only summarize scans that already exist in your account history, scoped by row-level security. If you have no completed scan for a category, that section will be empty — see the "no scan history" summary sentence in the generated report.',
          },
        ],
        related: [
          { label: 'Try the reports page', to: '/reports' },
          { label: 'Tutorial: Dashboard', to: '/tutorials/dashboard' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'How to generate and open a report',
        summary: 'The generation flow, title rules, and how signed links work in the UI.',
        readMinutes: 3,
        sections: [
          {
            kind: 'list',
            title: 'Steps in the page',
            items: [
              'Open /reports.',
              'Optionally set a report title (capped at 200 characters; defaults to "Security Audit Report").',
              'Click to generate the report.',
              'Find the new report at the top of the list.',
              'Click to open it — the app refreshes the list, takes the freshly signed URL and opens it in a new tab.',
            ],
          },
          {
            kind: 'text',
            title: 'About signed links',
            body: 'Every row in the list carries a signed URL issued at load time. The open action re-fetches the list to get a fresh signature so an expired link cannot break the button. Links expire by default after 3600 seconds and are re-issued on every list load.',
          },
          {
            kind: 'callout',
            title: 'Empty history',
            tone: 'primary',
            body: 'You can generate a report even with no scans on file: the PDF will state that no prior scan history was found and each category will be empty. Generate reports after you have run the tools so the audit contains real findings.',
          },
        ],
        related: [
          { label: 'Reading reports', to: '/tutorials/reports/reading-results' },
          { label: 'Tutorial: Website Scanner', to: '/tutorials/website-scanner' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading a generated report',
        summary: 'What the PDF contains, how categories map to your latest scans, and the list UI.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Report structure',
            body: 'The PDF mirrors your saved scan summaries: a website section (target, reachable flag, score, grade and check summary), an email section (subject, sender, predicted label, confidence and indicators), a password section (length, entropy, strength score and label, character classes, common-list flag) and a log section (parsed/event counts, anomaly count, severity and anomalies). Categories with no saved scan are absent or empty.',
          },
          {
            kind: 'text',
            title: 'The report list',
            body: 'The reports page lists your generated PDFs newest first with a relative timestamp (for example "2 hours ago"). Every row includes a signed open link. If a link has expired, refresh the list — a fresh signed URL is issued for each row on every load.',
          },
          {
            kind: 'example',
            title: 'Illustrative summary lines',
            inputLabel: 'Scenario',
            input: 'Two prior scans: one website scan (score 84) and one email scan (phishing)',
            outputLabel: 'Report summary (illustrative)',
            output: 'This report aggregates the most recent security scans on file for the account:\nwebsite, email.\nSections present: Website scan \u00b7 Email scan\nSections absent (no history): Password \u00b7 Log',
            detail: 'The backend builds the summary sentence from whichever of the four categories actually have saved scans.',
          },
          {
            kind: 'callout',
            title: 'Common mistakes',
            tone: 'warning',
            body: 'Expecting a report to include every scan you ever ran — it uses only the most recent completed scan per category. Expecting it to re-analyze anything — it is an aggregation of stored results. Treating a signed URL as permanent — it expires and must be re-fetched.',
          },
        ],
        related: [
          { label: 'How it works', to: '/tutorials/reports/under-the-hood' },
          { label: 'Tutorial: Reports', to: '/tutorials/reports' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How reports work behind the scenes',
        summary: 'The generation pipeline, signed-URL security, and the concepts behind private storage.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'Generate report reads your most recent row from each of the four scan tables (ordered by created_at, one per category), builds a JSON-serializable report_data snapshot, renders a PDF in a temporary directory with ReportLab, uploads the bytes to the private report-pdfs bucket under user_id/report_id.pdf, and inserts a public.reports row. Listing reads your report rows and attaches a fresh signed URL to each.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'In-memory rendering — the PDF is built in a temp dir that is cleaned up after upload.',
              'Private bucket with signed URLs — access expires, so a leaked link is time-limited.',
              'Least privilege — the bucket is never public and get_public_url is never used.',
              'User namespacing — object keys are scoped per user, with traversal protection.',
              'Data minimization — the report stores summaries, never raw email text, log lines or passwords.',
            ],
          },
          {
            kind: 'callout',
            title: 'Limitations',
            tone: 'primary',
            body: 'A report is a point-in-time snapshot of the most recent scan per category — it contains no live re-analysis and no scans you have not already completed and saved.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Share reports only with people who are authorized to see your findings, and never paste a signed URL publicly — it is time-limited but still a credential to the document.',
          },
        ],
        related: [
          { label: 'Tutorial: Dashboard', to: '/tutorials/dashboard' },
          { label: 'Try the reports page', to: '/reports' },
        ],
      },
    ],
  },
  {
    slug: 'cryptography-lab',
    title: 'Cryptography Lab',
    eyebrow: 'Security lab',
    description: 'Run real cryptographic primitives — hashing, encoding, AES-256-GCM, HMAC and secure randomness — locally with the Web Crypto API.',
    icon: ShieldCheck,
    toolLabel: 'Cryptography Lab',
    toolPath: '/cryptography-lab',
    status: 'ready',
    lessons: [
      {
        id: 'what-it-is',
        title: 'What the lab is',
        summary: 'Browser-first cryptographic primitives, the five modules, and why nothing ever leaves the page.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'The Cryptography Lab is browser-first. It runs SHA-256 and SHA-512 hashing, Base64 and Hex encoding, AES-256-GCM authenticated encryption, HMAC-SHA256 signing and verification, and secure randomness. All operations execute locally with the Web Crypto API.',
          },
          {
            kind: 'list',
            title: 'Modules to explore',
            items: [
              'Hashing — fixed-size one-way digests and the avalanche effect.',
              'Encoding — reversible Base64 and Hex, which is not encryption.',
              'AES-256-GCM — authenticated encryption with PBKDF2 key derivation.',
              'HMAC-SHA256 — keyed integrity and authenticity verification.',
              'Secure randomness — unpredictable bytes from the platform CSPRNG.',
            ],
          },
          {
            kind: 'callout',
            title: 'Kept private',
            tone: 'success',
            body: 'Plaintext, passphrases and keys never leave the browser. The lab does not call /api/crypto at all — the authenticated backend crypto endpoints are a separate, documented programmatic surface.',
          },
        ],
        related: [
          { label: 'Try the lab', to: '/cryptography-lab' },
          { label: 'Tutorial: Password Analyzer', to: '/tutorials/password-analyzer' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'How to use the lab',
        summary: 'A quick tour of each module — inputs to provide and what to do with the outputs.',
        readMinutes: 4,
        sections: [
          {
            kind: 'list',
            title: 'Hashing',
            items: [
              'Open the Hashing module and choose SHA-256 or SHA-512.',
              'Enter any text and hash it — the digest is 64 hex characters (256 bits) for SHA-256, 128 (512 bits) for SHA-512.',
              'Change one character and hash again to observe the avalanche effect.',
            ],
          },
          {
            kind: 'list',
            title: 'Encoding',
            items: [
              'Encode text into Base64 or hex, then decode it back.',
              'Notice that no key is involved — anyone can decode without a secret.',
            ],
          },
          {
            kind: 'list',
            title: 'AES-256-GCM',
            items: [
              'Enter a message and a passphrase (8\u2013512 characters).',
              'Encrypt it — you get ciphertext, salt, nonce and tag in Base64. Keep all of them.',
              'Paste them back to decrypt. A wrong passphrase or tampered ciphertext fails hard.',
            ],
          },
          {
            kind: 'list',
            title: 'HMAC-SHA256',
            items: [
              'Generate a random key (256 bits by default).',
              'Sign a message to get a 64-hex-character tag.',
              'Verify it, then change one character of the message and watch verification fail.',
            ],
          },
          {
            kind: 'list',
            title: 'Secure randomness',
            items: [
              'Pick a byte count and draw bytes with crypto.getRandomValues().',
              'Inspect the hex and Base64 views — this is where salts, nonces and keys come from.',
            ],
          },
        ],
        related: [
          { label: 'Reading the results', to: '/tutorials/cryptography-lab/reading-results' },
          { label: 'Tutorial: SQL Playground', to: '/tutorials/sql-playground' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading the results',
        summary: 'What each module\u2019s output means, what to preserve, and what "fails closed" behaviour looks like.',
        readMinutes: 5,
        sections: [
          {
            kind: 'text',
            title: 'Hashing output',
            body: 'The digest is irreversible and fixed-length regardless of input size. The digest-length readout (bits) doubles as a fingerprint of the message. Because hashing is deterministic, the same input always yields the same digest — that is what makes a one-character change produce a completely different-looking hash.',
          },
          {
            kind: 'text',
            title: 'Encoding output',
            body: 'Encoded text is exactly reversible without any secret. A Base64 or hex result is not protected in any way — encoding is a representation, not confidentiality. The encoding note in the result exists to make that explicit.',
          },
          {
            kind: 'text',
            title: 'AES-256-GCM output',
            body: 'Encryption returns ciphertext plus the salt (16 bytes), nonce/IV (12 bytes) and authentication tag (128 bits), all Base64-encoded. You must keep every one of them along with the passphrase to decrypt. The GCM tag makes decryption fail closed: the wrong passphrase or any tampering produces an error instead of silently returning garbage.',
          },
          {
            kind: 'text',
            title: 'HMAC output',
            body: 'Signing produces a 256-bit tag rendered as 64 hex characters. Verification passes only with the same key and the exact same message. The verify operation uses a constant-time comparison, avoiding timing leaks. HMAC authenticates a message; it does not hide it.',
          },
          {
            kind: 'text',
            title: 'Randomness output',
            body: 'Drawing bytes returns them with hex and Base64 views. Each byte carries up to 8 bits of entropy when drawn from a uniform CSPRNG, so a 32-byte draw provides up to 256 bits of unpredictable material.',
          },
          {
            kind: 'callout',
            title: 'Common mistakes',
            tone: 'warning',
            body: 'Treating Base64 or hex as encryption. Treating a hash as encrypted data. Reusing a nonce or salt across encryptions. Using short, easily guessed passphrases. Reaching for Math.random() for anything secret — the lab\u2019s random module uses the Web Crypto CSPRNG precisely because weak randomness breaks cryptography.',
          },
        ],
        related: [
          { label: 'How it works', to: '/tutorials/cryptography-lab/under-the-hood' },
          { label: 'Tutorial: Password Analyzer', to: '/tutorials/password-analyzer' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How the lab works behind the scenes',
        summary: 'The Web Crypto engine, key derivation details, the backend equivalent, and the concepts involved.',
        readMinutes: 6,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'The browser engine implements each module on top of the Web Crypto API. AES-256-GCM derives a 256-bit key from your passphrase with PBKDF2-HMAC-SHA256 at 600,000 iterations, drawing a fresh 16-byte salt and a 12-byte nonce on every encryption, and appends a 128-bit authentication tag. HMAC uses HMAC-SHA256. Randomness uses crypto.getRandomValues(). The engine enforces the 512-character passphrase cap itself, not only in the input field.',
          },
          {
            kind: 'text',
            title: 'The authenticated backend equivalent',
            body: 'Separate, authenticated endpoints exist under /api/crypto: hash (SHA-256/SHA-512, plus SHA-1 and MD5 exposed for educational deprecation study with warnings), AES-256-GCM encrypt/decrypt with the same PBKDF2 settings, and Base64/Hex encode/decode. Inputs are capped at 100,000 characters and passphrases must be at least 8 characters. The interactive lab does not use these endpoints; they log and store nothing.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'Hashing vs encryption — a digest cannot be reversed; encryption can.',
              'Encoding vs encryption — Base64/hex hide nothing.',
              'Key derivation — a passphrase is not the key; PBKDF2 stretches it with a random salt.',
              'Nonce uniqueness — a new nonce per message under the same key is mandatory for AES-GCM.',
              'Authenticated encryption — the tag detects tampering and wrong passphrases.',
              'Keyed integrity — HMAC proves message authenticity to key holders.',
              'CSPRNG — salts, nonces and keys must come from unpredictable randomness.',
            ],
          },
          {
            kind: 'callout',
            title: 'Limitations',
            tone: 'primary',
            body: 'The lab covers a small, modern set of primitives. RSA, ChaCha20, Diffie-Hellman, Vigen\u00e8re and other algorithms are not implemented. Browser-local secrets disappear when the page closes. HMAC exists client-side only — there is no HMAC API endpoint.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'This is a learning lab: do not protect real secrets with it. No secret material ever leaves your browser, which is the whole point — practice freely, and use the short sample passphrases and messages as the lab designs them to be used.',
          },
        ],
        related: [
          { label: 'Try the lab', to: '/cryptography-lab' },
          { label: 'Tutorial: Authentication & account', to: '/tutorials/authentication' },
        ],
      },
    ],
  },
  {
    slug: 'sql-playground',
    title: 'SQL Playground',
    eyebrow: 'Sandboxed lab',
    description: 'Learn SQL injection through two surfaces: a non-executing legacy demo and an authenticated lab on an isolated in-memory database.',
    icon: Bug,
    toolLabel: 'SQL Playground',
    toolPath: '/sql-playground',
    status: 'ready',
    lessons: [
      {
        id: 'two-surfaces',
        title: 'Two distinct surfaces',
        summary: 'How the public legacy demo differs from the authenticated educational lab.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'Legacy demo (public)',
            body: 'The legacy POST /api/sql/demo never executes SQL and never connects to a database. It renders an "unsafe" concatenated query string next to a parameterized version, reports which SQL metacharacter patterns your input triggered, and shows example outcomes. Purely illustrative.',
          },
          {
            kind: 'text',
            title: 'Authenticated lab',
            body: 'The educational lab (POST /api/sql/run with GET /api/sql/scenarios) runs only fixed SQL templates against a fresh in-memory SQLite database seeded with demo tables. Each run executes a vulnerable template (payload interpolated) and a secure one (payload bound as a parameter), side by side, so you see injection succeed against the vulnerable path and parameterization neutralize it on the safe path.',
          },
          {
            kind: 'list',
            title: 'Lab scenarios',
            items: [
              'login — authentication bypass with an always-true condition.',
              'union — UNION-based extraction of rows from another table.',
              'boolean — blind boolean-based inference using row counts.',
              'comment — comment-based filter bypass that truncates the query.',
            ],
          },
          {
            kind: 'callout',
            title: 'Not a real attack tool',
            tone: 'warning',
            body: 'You control only a scenario id and a 2048-character payload. Everything runs inside the isolated sandbox — it cannot be pointed at a real database, your network, or any cyber-shield production system.',
          },
        ],
        related: [
          { label: 'Try the playground', to: '/sql-playground' },
          { label: 'Tutorial: Log Analyzer', to: '/tutorials/log-analyzer' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'How to use the lab',
        summary: 'Choosing a scenario, entering a payload, and comparing the vulnerable and parameterized results.',
        readMinutes: 3,
        sections: [
          {
            kind: 'list',
            title: 'Steps in the page',
            items: [
              'Open /sql-playground.',
              'Pick a scenario from the dropdown (login, union, boolean or comment).',
              'Read the scenario description and the example payload.',
              'Click "Use example" or type your own payload (capped at 2048 characters).',
              'Run the demo and compare the vulnerable and parameterized result panels.',
              'Read the explanation cards: what happened, why the vulnerable query failed, why parameterization works, and the mitigation.',
            ],
          },
          {
            kind: 'text',
            title: 'The demo query preview',
            body: 'Below the form the page shows both templates: the vulnerable one interpolates the payload directly into the SQL string with {payload}, while the secure one uses ? placeholders. This preview makes the difference between string concatenation and parameter binding visible before you even run anything.',
          },
          {
            kind: 'text',
            title: 'The outcome banner',
            body: 'After a run, a banner summarizes the comparison: injection succeeded against the vulnerable implementation (vulnerable rows greater than zero while the safe path returned none), row counts differ between paths, or both returned the same rows.',
          },
        ],
        related: [
          { label: 'Reading the results', to: '/tutorials/sql-playground/reading-results' },
          { label: 'Tutorial: Cryptography Lab', to: '/tutorials/cryptography-lab' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading the results',
        summary: 'The two result tables, rejection reasons, and a verified worked example on the login scenario.',
        readMinutes: 5,
        sections: [
          {
            kind: 'text',
            title: 'Two result tables',
            body: 'The "Vulnerable implementation" panel shows the interpolated query and its result set; the "Parameterized implementation" panel shows the bound query and its result set. Both report row count, column count and execution status (ok or rejected). A rejected path shows a generic reason only — the sandbox never leaks sqlite internals.',
          },
          {
            kind: 'text',
            title: 'Rejection messages',
            body: 'Rejections are deliberately generic: "multiple statements are not allowed", "blocked by the sandbox guard", "maximum query work exceeded", "SQL syntax was rejected", or a generic fallback. These map internal sqlite errors to safe, educational text.',
          },
          {
            kind: 'example',
            title: 'Worked example: login bypass',
            inputLabel: 'Scenario + payload',
            input: 'Scenario: login\nPayload: \' OR \'1\'=\'1',
            outputLabel: 'Result (verified output)',
            output: 'Vulnerable query:\nSELECT id, username, role FROM users\nWHERE username = \'\' OR \'1\'=\'1\' AND role = \'user\' ORDER BY id;\n-> 3 rows (alice, bob, carol)\n\nParameterized query:\nWHERE username = ? AND role = ?\n-> 0 rows\n\nSandbox: in-memory sqlite (isolated, non-persistent)',
            detail: 'Verified by running the actual lab service. The payload closes the string literal and adds an always-true OR, so the vulnerable path returns every regular user instead of one. The parameterized path treats the whole payload as a literal username value and matches nothing.',
          },
          {
            kind: 'callout',
            title: 'Common mistakes',
            tone: 'warning',
            body: 'Expecting access to real tables or production data — reads are restricted to the demo tables users, products and orders. Trying multi-statement payloads such as \'"; DROP TABLE" — the sandbox rejects multiple statements and any write or DDL. Reading a rejected vulnerable path as proof of a "stronger app" — it reflects the sandbox\u2019s authorizer, not your own SQL.',
          },
        ],
        related: [
          { label: 'How it works', to: '/tutorials/sql-playground/under-the-hood' },
          { label: 'Tutorial: Log Analyzer', to: '/tutorials/log-analyzer' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How the sandbox works',
        summary: 'The guardrails that keep the lab isolated, the two execution paths, and the concepts it teaches.',
        readMinutes: 5,
        sections: [
          {
            kind: 'list',
            title: 'Sandbox guardrails',
            items: [
              'Fixed scenario allowlist — only the four bundled templates exist.',
              'A fresh in-memory SQLite database per call, seeded with users, products and orders and closed on exit — no state survives.',
              'An authorizer that permits SELECT on the demo tables only and denies writes, DDL, ATTACH/DETACH, PRAGMA and load_extension.',
              'A progress budget (100,000 steps) that aborts pathological work.',
              'A cap of 100 result rows and a 1 MB per-cell size limit at the SQLite engine level.',
              'JSON-safe, bounded result cells, and generic rejection messages.',
              'No persistence, no network, no PostgreSQL, no Supabase — and no arbitrary-SQL entry point.',
            ],
          },
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'For each run the service interpolates your payload into the fixed vulnerable template, binds it as a parameter in the secure template, and executes both against the same fresh in-memory database. Result cells are sanitized (binary blobs become a fixed marker; oversized text is truncated) and every failure is mapped to one of the generic reasons before being returned in the explanation object.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'Parameterization — bound placeholders make injected input data, never code.',
              'SQL injection flavours — boolean, UNION, authentication bypass and comment truncation.',
              'Least privilege — the sandbox account can only read three tables.',
              'Defense in depth — allowlist, authorizer, budget, size caps and generic errors all work together.',
            ],
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Practice SQL injection only inside this sandbox. Never attempt the payloads against third-party systems — you do not own them and have no permission. Use the mitigation advice in your own application code, where parameterized queries are the fix.',
          },
        ],
        related: [
          { label: 'Try the playground', to: '/sql-playground' },
          { label: 'Tutorial: Website Scanner', to: '/tutorials/website-scanner' },
        ],
      },
    ],
  },
  {
    slug: 'dashboard',
    title: 'Dashboard',
    eyebrow: 'Security overview',
    description: 'Aggregate your scan history into a security score, activity metrics, recent scans and a 12-day trend.',
    icon: LayoutDashboard,
    toolLabel: 'Dashboard',
    toolPath: '/dashboard',
    status: 'ready',
    lessons: [
      {
        id: 'what-it-shows',
        title: 'What the dashboard shows',
        summary: 'The four headline metrics and where each one comes from.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'The dashboard aggregates the four scan tables plus your reports into one view. Every metric is derived from rows that already exist in your account: nothing is synthesized and nothing is guessed.',
          },
          {
            kind: 'list',
            title: 'The four metrics',
            items: [
              'security_score — the average of your website scan scores (0\u2013100).',
              'scans_completed — every scan you have run, plus how many were completed this week.',
              'threats_detected — scans rated risky: website/email/log rows with high or critical risk, or password scans that are breached, Weak or Fair.',
              'assets_monitored — the number of distinct website targets you have scanned.',
            ],
          },
          {
            kind: 'list',
            title: 'Sections',
            items: [
              'Four metric cards at the top, each with a value and a detail line.',
              'A recent-scans table with target, type, risk and completion time.',
              'An activity feed of scan and report events.',
              'A 12-day threat trend chart (UTC, includes zero-value days).',
            ],
          },
          {
            kind: 'callout',
            title: 'Only your own data',
            tone: 'primary',
            body: 'Every row is scoped to your user id by row-level security, so the dashboard reflects exactly what your account has scanned and nothing else.',
          },
        ],
        related: [
          { label: 'Open the dashboard', to: '/dashboard' },
          { label: 'Tutorial: Reports', to: '/tutorials/reports' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'How to use the dashboard',
        summary: 'Reading the cards, recent scans and activity, and how new data arrives.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Reading the page',
            body: 'Open /dashboard after you have signed in. The metric cards give an at-a-glance picture: your average website score, how much you have exercised the tools, how many findings need attention, and how many distinct targets you monitor.',
          },
          {
            kind: 'list',
            title: 'Practical tips',
            items: [
              'Use the recent-scans list to jump back into the tool that produced a result.',
              'Watch the detail line under each metric — it explains the exact computation (for example "Average across 3 website scan(s)").',
              'Treat the trend chart as history: each day counts the scans saved that day, including days with zero.',
              'Run new scans or generate reports, then reload the dashboard to see them reflected in the metrics and activity feed.',
            ],
          },
          {
            kind: 'callout',
            title: 'An empty dashboard is normal',
            tone: 'primary',
            body: 'Before you have run anything, metrics show 0 and detail lines say things like "No website scans on file". That is expected, not a fault — the dashboard only reports what your account has persisted.',
          },
        ],
        related: [
          { label: 'Tutorial: Website Scanner', to: '/tutorials/website-scanner' },
          { label: 'Tutorial: Authentication & account', to: '/tutorials/authentication' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading the metrics and lists',
        summary: 'Metric semantics, the recent-scans risk column, the activity feed, and the trend chart.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Metric semantics',
            body: 'security_score is the average of your website scan scores, rounded. scans_completed counts all rows across the four scan tables with a "N this week" breakdown. threats_detected counts risky rows: website/email/log at high or critical risk, or password rows that match the common list or scored Weak/Fair. assets_monitored counts distinct target URLs in your website scan history.',
          },
          {
            kind: 'text',
            title: 'Recent scans and activity',
            body: 'Each recent-scan row shows the target (for password scans, a generic "Password analysis"), the analysis type, a human-friendly risk value, and the completion timestamp. For password rows the displayed risk is derived from the strength label and the breached flag rather than a stored risk column. The activity feed lists your scan completions and report generations, newest first, capped at ten entries.',
          },
          {
            kind: 'text',
            title: 'The trend chart',
            body: 'The 12-day trend counts scans saved per calendar day in UTC, including zero-value days, so gaps in activity are visible rather than hidden. The dashboard endpoint computes it from your stored rows alongside the metrics.',
          },
          {
            kind: 'callout',
            title: 'How results appear here',
            tone: 'primary',
            body: 'Only completed, persisted results show up: unreachable website scans and rows that were never stored never reach the dashboard. If a scan you just ran is missing, confirm it completed successfully first.',
          },
        ],
        related: [
          { label: 'Tutorial: Password Analyzer', to: '/tutorials/password-analyzer' },
          { label: 'Open the dashboard', to: '/dashboard' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How the dashboard works behind the scenes',
        summary: 'The aggregation endpoint, RLS scoping, zero-day trend math, and the concepts involved.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'GET /api/dashboard reads your website_scans, email_scans, password_scans and log_scans plus the reports table through a user-scoped client authenticated with your access token. The user id comes from the verified JWT only — request body and query parameters are ignored. The service computes the metrics, recent scans, activity feed and a 12-day trend (including zero-value days) in Python and returns the envelope.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'Row-level security — every aggregation query is scoped to auth.uid().',
              'JWT identity — user_id is never taken from the client.',
              'Least privilege — the elevated admin client is never used for user data.',
              'Data minimization — passwords, hashes, raw email text and raw logs are never returned by this endpoint.',
            ],
          },
          {
            kind: 'callout',
            title: 'Limitations',
            tone: 'primary',
            body: 'The dashboard is an aggregation of already-persisted results, so it is only as current as your last completed scan or report. It is not a real-time monitoring or live-streaming panel.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Your dashboard only ever sees your own activity. Use it to review your practice history and spot trends — not to infer anything about other users, which the RLS scoping makes impossible anyway.',
          },
        ],
        related: [
          { label: 'Tutorial: Reports', to: '/tutorials/reports' },
          { label: 'Tutorial: Log Analyzer', to: '/tutorials/log-analyzer' },
        ],
      },
    ],
  },
  {
    slug: 'authentication',
    title: 'Authentication & account',
    eyebrow: 'Identity',
    description: 'How sign-in, sign-up and password reset work with Supabase Auth, and the account surface in this app.',
    icon: UserRound,
    toolLabel: 'Profile',
    toolPath: '/profile',
    status: 'ready',
    lessons: [
      {
        id: 'how-auth-works',
        title: 'How authentication works',
        summary: 'Supabase owns identity; the Flask API only verifies the JWT and reads your profile.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Overview',
            body: 'Supabase Auth owns sign-up, sign-in, sessions and password hashing. Your browser talks to Supabase directly, and every API call then carries a Bearer access token. The Flask backend exposes a single authenticated auth endpoint — GET /api/auth/me — which reads public.profiles through a user-scoped client keyed off the verified JWT.',
          },
          {
            kind: 'text',
            title: 'Where identity lives',
            body: 'The server verifies each token (algorithm, audience and issuer are configurable, with keys fetched from the project JWKS endpoint). The user id always comes from the verified JWT sub claim — never from the request body — and row-level security scopes every data read and write to that id.',
          },
          {
            kind: 'list',
            title: 'Related surfaces',
            items: [
              '/login — sign in to your workspace.',
              '/register — create an account.',
              '/forgot-password — request a password-reset link.',
              '/profile and /settings — account identity and workspace preferences.',
            ],
          },
          {
            kind: 'callout',
            title: 'No local password storage',
            tone: 'success',
            body: 'The backend never stores passwords locally. Password hashing and session management are entirely delegated to Supabase-managed identity.',
          },
        ],
        related: [
          { label: 'Tutorial: Dashboard', to: '/tutorials/dashboard' },
          { label: 'Tutorial: Password Analyzer', to: '/tutorials/password-analyzer' },
        ],
      },
      {
        id: 'how-to-use',
        title: 'How to sign up, sign in and manage your account',
        summary: 'The concrete flows for registration, sign-in, password reset and sign-out.',
        readMinutes: 3,
        sections: [
          {
            kind: 'list',
            title: 'Create an account',
            items: [
              'Open /register.',
              'Enter your email, a password, and optionally a full name.',
              'Submit — Supabase creates the account and you can then sign in.',
            ],
          },
          {
            kind: 'list',
            title: 'Sign in',
            items: [
              'Open /login and enter your email and password.',
              'Supabase returns a session; the app stores it and attaches the access token to API calls.',
              'Protected console routes unlock once the session is active.',
            ],
          },
          {
            kind: 'list',
            title: 'Forgot password',
            items: [
              'Open /forgot-password and enter your email.',
              'Supabase sends a reset link; follow it to set a new password.',
            ],
          },
          {
            kind: 'list',
            title: 'Sign out and account pages',
            items: [
              'Sign out from the account menu — the session is cleared client-side.',
              'Open /profile to view account identity (a demo display of your name, email and avatar).',
              'Open /settings to see preference controls (a demo surface — they are not persisted).',
            ],
          },
        ],
        related: [
          { label: 'Tutorial: Website Scanner', to: '/tutorials/website-scanner' },
          { label: 'Tutorial: Password Analyzer', to: '/tutorials/password-analyzer' },
        ],
      },
      {
        id: 'reading-results',
        title: 'Reading sessions, tokens and account data',
        summary: 'What the Bearer token means, how 401s feel, and what /profile actually displays.',
        readMinutes: 3,
        sections: [
          {
            kind: 'text',
            title: 'Tokens and requests',
            body: 'Every authenticated request from the frontend appends Authorization: Bearer <token> via the shared API client. The backend validates the token before the route runs; an expired or invalid token returns 401 with the standard error envelope. Signing out removes the session from the browser.',
          },
          {
            kind: 'text',
            title: 'Account identity',
            body: '/profile renders your identity from the Supabase user metadata — name, email and avatar source. The /api/auth/me endpoint returns the matching public.profiles row (or a minimal profile containing only your id if none is set), always keyed to your verified JWT.',
          },
          {
            kind: 'callout',
            title: 'Common mistakes',
            tone: 'warning',
            body: 'Sharing passwords or tokens with others — they would control your account. Expecting Flask to manage passwords — it does not; Supabase does. Expecting /profile or /settings to persist changes — those are static demo surfaces today, not working storage.',
          },
        ],
        related: [
          { label: 'Open /profile', to: '/profile' },
          { label: 'Tutorial: Reports', to: '/tutorials/reports' },
        ],
      },
      {
        id: 'under-the-hood',
        title: 'How auth works behind the scenes',
        summary: 'The Supabase-to-Flask handoff, JWT verification, RLS, and the security concepts involved.',
        readMinutes: 4,
        sections: [
          {
            kind: 'text',
            title: 'What happens internally',
            body: 'Sign-up, sign-in and logout run entirely through the Supabase JavaScript client in the browser. The Flask backend verifies the access token with PyJWT using configurable algorithm, audience, issuer and JWKS settings (with a small clock-skew allowance), then treats the validated sub claim as the user id. All user-data reads and writes flow through a user-scoped client so row-level security scopes every query to that id.',
          },
          {
            kind: 'list',
            title: 'Security concepts in play',
            items: [
              'Credential storage offloaded — secrets are handled by Supabase, not your application.',
              'JWT verification — the API trusts only tokens it can validate.',
              'Row-level security — even if a query leaked, it would return nothing outside your rows.',
              'Defense in depth — HTTPS in production, hardened headers, payload limits and generic error envelopes protect the rest of the stack.',
            ],
          },
          {
            kind: 'callout',
            title: 'Limitations',
            tone: 'primary',
            body: 'Flask exposes only /me for auth. The /profile and /settings pages are demo surfaces with no backend persistence. Multi-factor authentication, role-based access control and password-change flows are planned future work, not present features.',
          },
          {
            kind: 'callout',
            title: 'Safe and ethical use',
            tone: 'success',
            body: 'Use a strong, unique password for your account — the Password Analyzer tutorial shows how to judge one. Never share credentials or tokens, and only manage your own account. The skills here generalize to any service you build.',
          },
        ],
        related: [
          { label: 'Tutorial: Password Analyzer', to: '/tutorials/password-analyzer' },
          { label: 'Tutorial: Cryptography Lab', to: '/tutorials/cryptography-lab' },
        ],
      },
    ],
  },
  {
    slug: 'ai-ml',
    title: 'AI/ML analysis',
    eyebrow: 'Planned',
    description: 'Planned area for model-backed analysis. Not yet implemented — the current analyzers are rule-based.',
    icon: Brain,
    toolLabel: '',
    toolPath: null,
    status: 'planned',
    lessons: [],
  },
];

export function getTutorialArea(slug: string): TutorialArea | undefined {
  return tutorialAreas.find((area) => area.slug === slug);
}

export function getTutorialLesson(areaSlug: string, lessonId: string): TutorialArea['lessons'][number] | undefined {
  return getTutorialArea(areaSlug)?.lessons.find((lesson) => lesson.id === lessonId);
}
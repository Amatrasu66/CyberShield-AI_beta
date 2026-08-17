import type { LucideIcon } from 'lucide-react';
import { BarChart3, Bug, FileText, KeyRound, LayoutDashboard, MailWarning, ScanSearch, Settings, ShieldCheck, UserRound } from 'lucide-react';

export type NavItem = { label: string; to: string; icon: LucideIcon };
export const navigation: readonly NavItem[] = [
  { label: 'Dashboard', to: '/dashboard', icon: LayoutDashboard }, { label: 'Website Scanner', to: '/website-scanner', icon: ScanSearch },
  { label: 'Email Detector', to: '/phishing-detector', icon: MailWarning }, { label: 'Password Analyzer', to: '/password-analyzer', icon: KeyRound },
  { label: 'Log Analyzer', to: '/log-analyzer', icon: BarChart3 }, { label: 'Reports', to: '/reports', icon: FileText },
  { label: 'SQL Playground', to: '/sql-playground', icon: Bug }, { label: 'Cryptography Lab', to: '/cryptography-lab', icon: ShieldCheck },
];

export const userNav: readonly NavItem[] = [{ label: 'Profile', to: '/profile', icon: UserRound }, { label: 'Settings', to: '/settings', icon: Settings }];
export const dashboardMetrics = [
  { label: 'Security score', value: '84', detail: '+6% from last month', tone: 'success' },
  { label: 'Scans completed', value: '128', detail: '24 this week', tone: 'primary' },
  { label: 'Threats detected', value: '12', detail: '3 require attention', tone: 'danger' },
  { label: 'Assets monitored', value: '36', detail: 'All systems online', tone: 'warning' },
] as const;
export const recentScans = [
  ['api.cybershield.dev', 'Website scan', 'Low', '2 min ago'], ['Finance-Q2.log', 'Log analysis', 'Medium', '34 min ago'], ['Partner email', 'Email detector', 'High', '1 hr ago'], ['auth.cybershield.dev', 'Website scan', 'Low', 'Yesterday'],
] as const;
export const activity = ['Scheduled scan completed for api.cybershield.dev', 'New phishing indicator detected in Partner email', 'Monthly security report is ready to review'];

export type ToolSpec = { eyebrow: string; title: string; description: string; inputLabel: string; inputPlaceholder: string; action: string; resultTitle: string; resultValue: string; resultDetail: string; rows: readonly (readonly string[])[]; tableHeaders: readonly string[]; status: 'success' | 'warning' | 'danger' | 'primary' };
export const tools: Record<string, ToolSpec> = {
  '/website-scanner': { eyebrow: 'Attack surface', title: 'Website Security Scanner', description: 'Inspect a public URL for headers, TLS posture, and common configuration weaknesses.', inputLabel: 'Target URL', inputPlaceholder: 'https://example.com', action: 'Start security scan', resultTitle: 'Overall security score', resultValue: '84 / 100', resultDetail: 'No critical vulnerabilities identified in this demo result.', tableHeaders: ['Check', 'Status', 'Finding'], rows: [['SSL certificate', 'Passed', 'Valid for 297 days'], ['Security headers', 'Warning', '2 recommended headers missing'], ['Cookie policy', 'Passed', 'Secure and HttpOnly configured']], status: 'warning' },
  '/phishing-detector': { eyebrow: 'Email intelligence', title: 'Phishing Email Detector', description: 'Analyze suspicious message content for phishing language and risky indicators.', inputLabel: 'Email content', inputPlaceholder: 'Paste a suspicious email message here…', action: 'Analyze email', resultTitle: 'Risk classification', resultValue: 'Likely phishing', resultDetail: 'Demo indicators: urgent language, mismatched sender, and credential request.', tableHeaders: ['Indicator', 'Severity', 'Evidence'], rows: [['Urgency language', 'High', '“Action required immediately”'], ['Suspicious link', 'High', 'Lookalike domain'], ['Personalization', 'Low', 'Generic greeting']], status: 'danger' },
  '/password-analyzer': { eyebrow: 'Credential hygiene', title: 'Password Strength Analyzer', description: 'Measure password strength using length, entropy, patterns, and common exposure signals.', inputLabel: 'Password to assess', inputPlaceholder: 'Enter a demo password', action: 'Analyze password', resultTitle: 'Strength rating', resultValue: 'Strong', resultDetail: 'Estimated crack time exceeds one century in this static example.', tableHeaders: ['Signal', 'Status', 'Detail'], rows: [['Length', 'Passed', '18 characters'], ['Character variety', 'Passed', 'Upper, lower, number, symbol'], ['Known patterns', 'Passed', 'No common sequence']], status: 'success' },
};

export const authContent = {
  login: { title: 'Welcome back', description: 'Sign in to access your CyberShield AI workspace.', action: 'Sign in', prompt: 'New to CyberShield AI?', link: 'Create an account', to: '/register' },
  register: { title: 'Create your workspace', description: 'Start exploring your security posture with a guided demo.', action: 'Create account', prompt: 'Already have an account?', link: 'Sign in', to: '/login' },
  forgot: { title: 'Reset your password', description: 'Enter your email and we will send reset instructions.', action: 'Send reset link', prompt: 'Remembered your password?', link: 'Back to sign in', to: '/login' },
} as const;

import { useEffect } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { initTheme } from './hooks/useTheme';
import { RequireAuth, RequireGuest } from './components/AuthGuards';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import { SQLPlaygroundPage } from './pages/SQLPlaygroundPage';
import { CryptographyLabPage } from './pages/CryptographyLabPage';
import { EmailDetectorPage } from './pages/EmailDetectorPage';
import { WebsiteScannerPage } from './pages/WebsiteScannerPage';
import { PasswordAnalyzerPage } from './pages/PasswordAnalyzerPage';
import { LogAnalyzerPage } from './pages/LogAnalyzerPage';
import { ReportsPage } from './pages/ReportsPage';
import { PortScannerPage } from './pages/PortScannerPage';
import { NotFoundPage, ProfilePage, SettingsPage } from './pages/WorkspacePages';
import { TutorialsIndexPage } from './pages/tutorials/TutorialsIndexPage';
import { TutorialAreaPage } from './pages/tutorials/TutorialAreaPage';
import { TutorialLessonPage } from './pages/tutorials/TutorialLessonPage';
import { AuthCallbackPage } from './pages/AuthCallbackPage';
import { ResetPasswordPage } from './pages/ResetPasswordPage';

export interface AppProps { readonly initialPath?: string; }
function ConsoleRoutes() {
  return <RequireAuth><AppShell><Routes><Route path="/dashboard" element={<DashboardPage />} /><Route path="/website-scanner" element={<WebsiteScannerPage />} /><Route path="/phishing-detector" element={<EmailDetectorPage />} /><Route path="/password-analyzer" element={<PasswordAnalyzerPage />} /><Route path="/log-analyzer" element={<LogAnalyzerPage />} /><Route path="/sql-playground" element={<SQLPlaygroundPage />} /><Route path="/cryptography-lab" element={<CryptographyLabPage />} /><Route path="/port-scanner" element={<PortScannerPage />} /><Route path="/reports" element={<ReportsPage />} /><Route path="/tutorials" element={<TutorialsIndexPage />} /><Route path="/tutorials/:area" element={<TutorialAreaPage />} /><Route path="/tutorials/:area/:lesson" element={<TutorialLessonPage />} /><Route path="/profile" element={<ProfilePage />} /><Route path="/settings" element={<SettingsPage />} /><Route path="*" element={<NotFoundPage />} /></Routes></AppShell></RequireAuth>;
}
export default function App({ initialPath }: AppProps) {
  useEffect(() => {
    initTheme();
  }, []);
  return <Routes><Route path="/login" element={<RequireGuest><AuthPage mode="login" /></RequireGuest>} /><Route path="/register" element={<RequireGuest><AuthPage mode="register" /></RequireGuest>} /><Route path="/forgot-password" element={<RequireGuest><AuthPage mode="forgot" /></RequireGuest>} /><Route path="/auth/callback" element={<AuthCallbackPage />} /><Route path="/reset-password" element={<ResetPasswordPage />} /><Route path="/" element={<Navigate to={initialPath ?? '/dashboard'} replace />} /><Route path="/*" element={<ConsoleRoutes />} /></Routes>;
}

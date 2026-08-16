import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { RequireAuth, RequireGuest } from './components/AuthGuards';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import { ToolPage } from './pages/ToolPage';
import { WebsiteScannerPage } from './pages/WebsiteScannerPage';
import { NotFoundPage, ProfilePage, ReportsPage, SettingsPage } from './pages/WorkspacePages';

export interface AppProps { readonly initialPath?: string; }
function ConsoleRoutes() {
  return <RequireAuth><AppShell><Routes><Route path="/dashboard" element={<DashboardPage />} /><Route path="/website-scanner" element={<WebsiteScannerPage />} /><Route path="/phishing-detector" element={<ToolPage path="/phishing-detector" />} /><Route path="/password-analyzer" element={<ToolPage path="/password-analyzer" />} /><Route path="/log-analyzer" element={<ToolPage path="/log-analyzer" />} /><Route path="/sql-playground" element={<ToolPage path="/sql-playground" />} /><Route path="/cryptography-lab" element={<ToolPage path="/cryptography-lab" />} /><Route path="/reports" element={<ReportsPage />} /><Route path="/profile" element={<ProfilePage />} /><Route path="/settings" element={<SettingsPage />} /><Route path="*" element={<NotFoundPage />} /></Routes></AppShell></RequireAuth>;
}
export default function App({ initialPath }: AppProps) { return <Routes><Route path="/login" element={<RequireGuest><AuthPage mode="login" /></RequireGuest>} /><Route path="/register" element={<RequireGuest><AuthPage mode="register" /></RequireGuest>} /><Route path="/forgot-password" element={<RequireGuest><AuthPage mode="forgot" /></RequireGuest>} /><Route path="/" element={<Navigate to={initialPath ?? '/dashboard'} replace />} /><Route path="/*" element={<ConsoleRoutes />} /></Routes>; }

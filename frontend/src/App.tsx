import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { AuthPage } from './pages/AuthPage';
import { DashboardPage } from './pages/DashboardPage';
import { ToolPage } from './pages/ToolPage';
import { NotFoundPage, ProfilePage, ReportsPage, SettingsPage } from './pages/WorkspacePages';

export interface AppProps { readonly initialPath?: string; }
function ConsoleRoutes() { return <AppShell><Routes><Route path="/dashboard" element={<DashboardPage />} /><Route path="/website-scanner" element={<ToolPage path="/website-scanner" />} /><Route path="/phishing-detector" element={<ToolPage path="/phishing-detector" />} /><Route path="/password-analyzer" element={<ToolPage path="/password-analyzer" />} /><Route path="/log-analyzer" element={<ToolPage path="/log-analyzer" />} /><Route path="/sql-playground" element={<ToolPage path="/sql-playground" />} /><Route path="/cryptography-lab" element={<ToolPage path="/cryptography-lab" />} /><Route path="/reports" element={<ReportsPage />} /><Route path="/profile" element={<ProfilePage />} /><Route path="/settings" element={<SettingsPage />} /><Route path="*" element={<NotFoundPage />} /></Routes></AppShell>; }
export default function App({ initialPath }: AppProps) { return <Routes><Route path="/login" element={<AuthPage mode="login" />} /><Route path="/register" element={<AuthPage mode="register" />} /><Route path="/forgot-password" element={<AuthPage mode="forgot" />} /><Route path="/" element={<Navigate to={initialPath ?? '/dashboard'} replace />} /><Route path="/*" element={<ConsoleRoutes />} /></Routes>; }

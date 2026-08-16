export interface ApiErrorInfo {
  readonly code: string;
  readonly details?: unknown;
}

export interface ApiSuccessResponse<T = unknown> {
  readonly success: true;
  readonly message: string;
  readonly data: T;
  readonly meta?: Record<string, unknown>;
}

export interface ApiErrorResponse {
  readonly success: false;
  readonly message: string;
  readonly error: ApiErrorInfo;
}

export type ApiResponse<T = unknown> = ApiSuccessResponse<T> | ApiErrorResponse;

export type AuthProvider = 'email' | 'phone' | 'github' | 'google' | 'apple' | 'twitter' | 'sso';

export interface AuthUser {
  readonly id: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly avatarUrl: string | null;
  readonly createdAt: string | null;
  readonly provider: AuthProvider | null;
}

export interface AuthSession {
  readonly accessToken: string;
  readonly refreshToken: string | null;
  readonly expiresAt: number | null;
  readonly user: AuthUser | null;
}

export interface UserProfile {
  readonly id: string;
  readonly full_name: string | null;
  readonly role: string | null;
  readonly created_at: string | null;
  readonly updated_at: string | null;
}

export interface DashboardMetric {
  readonly value: number;
  readonly detail: string;
  readonly tone: 'success' | 'primary' | 'danger' | 'warning';
}

export interface DashboardMetrics {
  readonly security_score: DashboardMetric;
  readonly scans_completed: DashboardMetric;
  readonly threats_detected: DashboardMetric;
  readonly assets_monitored: DashboardMetric;
}

export interface DashboardRecentScan {
  readonly target: string;
  readonly type: string;
  readonly risk: string;
  readonly completed_at: string | null;
}

export interface DashboardActivity {
  readonly message: string;
  readonly created_at: string | null;
}

export interface DashboardTrend {
  readonly labels: readonly string[];
  readonly values: readonly number[];
}

export interface DashboardData {
  readonly metrics: DashboardMetrics;
  readonly recent_scans: readonly DashboardRecentScan[];
  readonly activity: readonly DashboardActivity[];
  readonly trend: DashboardTrend;
}

export type EmailRiskLevel = 'phishing' | 'suspicious' | 'safe';

export type EmailIndicatorSeverity = 'High' | 'Medium' | 'Low';

export interface EmailIndicator {
  readonly name: string;
  readonly severity: EmailIndicatorSeverity;
  readonly evidence: string;
}

export interface EmailAnalysisStats {
  readonly word_count: number;
  readonly link_count: number;
}

export interface EmailAnalysisResult {
  readonly is_phishing: boolean;
  readonly risk_level: EmailRiskLevel;
  readonly risk_score: number;
  readonly confidence: number;
  readonly analyzer: string;
  readonly summary: string;
  readonly indicators: readonly EmailIndicator[];
  readonly stats: EmailAnalysisStats;
}

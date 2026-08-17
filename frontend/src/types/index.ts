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

export type PasswordStrengthLabel = 'Weak' | 'Fair' | 'Good' | 'Strong';

export interface PasswordRecommendation {
  readonly text: string;
  readonly priority: number;
}

export interface PasswordWeakness {
  readonly code: string;
  readonly severity: 'critical' | 'high' | 'medium' | 'low';
  readonly title: string;
  readonly message: string;
  readonly recommendation: string;
}

export interface PasswordScoreBreakdown {
  readonly factor: string;
  readonly score: number;
  readonly status: 'good' | 'warning' | 'danger';
  readonly details: string;
}

export interface PasswordChecklistItem {
  readonly item: string;
  readonly status: 'passed' | 'failed' | 'advisory';
  readonly passed: boolean | null;
  readonly details: string;
}

export interface PasswordCharacterClasses {
  readonly uppercase: boolean;
  readonly lowercase: boolean;
  readonly digits: boolean;
  readonly special: boolean;
}

export interface PasswordAnalysisResult {
  readonly length: number;
  readonly char_classes: readonly string[];
  readonly uppercase: boolean;
  readonly lowercase: boolean;
  readonly digits: boolean;
  readonly special: boolean;
  readonly classes_used: number;
  readonly entropy_bits: number;
  readonly crack_time_estimate: string;
  readonly in_common_list: boolean;
  readonly strength_score: number;
  readonly strength: PasswordStrengthLabel;
  readonly recommendations: readonly PasswordRecommendation[];
  readonly weaknesses: readonly PasswordWeakness[];
  readonly score_breakdown: readonly PasswordScoreBreakdown[];
  readonly security_checklist: readonly PasswordChecklistItem[];
}

export type PasswordGenerationType = 'passphrase' | 'random';

export interface PasswordGenerateRequest {
  readonly type: PasswordGenerationType;
  readonly words?: number;
  readonly length?: number;
  readonly delimiter?: string;
}

export interface PasswordGenerateResult {
  readonly password: string;
  readonly type: PasswordGenerationType;
  readonly words?: number;
  readonly length?: number;
  readonly delimiter?: string;
  readonly charset_size?: number;
}

export interface LogAnomaly {
  readonly line_number: number | null;
  readonly type: string;
  readonly severity: 'High' | 'Medium' | 'Low';
  readonly evidence: string;
}

export interface LogAnalysisStats {
  readonly status_code_counts: Record<string, number>;
  readonly unique_ips: number;
  readonly top_sources: readonly [string, number][];
}

export interface LogAnalysisResult {
  readonly total_lines: number;
  readonly parsed_lines: number;
  readonly skipped_lines: number;
  readonly anomalies_detected: number;
  readonly threat_score: number;
  readonly severity: 'low' | 'medium' | 'high';
  readonly analyzer: string;
  readonly summary: string;
  readonly stats: LogAnalysisStats;
  readonly anomalies: readonly LogAnomaly[];
}

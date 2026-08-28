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
  readonly target?: string | null;
  readonly type?: string | null;
  readonly risk_level?: string | null;
  readonly status?: string | null;
  readonly resolved_ip?: string | null;
  readonly ports_scanned?: number | null;
  readonly open_port_count?: number | null;
  readonly threat_assessment?: ThreatAssessment | null;
  readonly ip_reputation?: IPReputationResult | null;
  readonly threat_intelligence?: ThreatIntelligenceBundle | null;
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

export interface ReportWebsiteScanData {
  readonly target: string | null;
  readonly reachable: boolean;
  readonly score: number | null;
  readonly grade: string | null;
  readonly summary: string | null;
  readonly checks: readonly unknown[];
}

export interface ReportEmailScanData {
  readonly subject: string | null;
  readonly sender_email: string | null;
  readonly predicted_label: string | null;
  readonly risk_level: string | null;
  readonly confidence: number | null;
  readonly analyzer: string | null;
  readonly indicators: readonly unknown[];
}

export interface ReportPasswordScanData {
  readonly length: number | null;
  readonly password_length: number | null;
  readonly entropy_bits: number | null;
  readonly strength_score: number | null;
  readonly strength: string | null;
  readonly strength_label: string | null;
  readonly in_common_list: boolean | null;
  readonly char_classes: readonly string[];
  readonly recommendations: readonly unknown[];
}

export interface ReportLogScanData {
  readonly parsed_lines: number | null;
  readonly event_count: number | null;
  readonly anomalies_detected: number | null;
  readonly anomaly_count: number | null;
  readonly severity: string | null;
  readonly risk_level: string | null;
  readonly analyzer: string | null;
  readonly anomalies: readonly unknown[];
}

export interface ReportPortScanData {
  readonly target: string | null;
  readonly resolved_ip: string | null;
  readonly scan_duration_ms: number | null;
  readonly ports_scanned: number | null;
  readonly open_ports: readonly unknown[];
  readonly open_port_count: number | null;
  readonly closed_ports: number | null;
  readonly filtered_ports: number | null;
  readonly risk_level: string | null;
  readonly status: string | null;
  readonly created_at: string | null;
  readonly ip_reputation: IPReputationResult | null;
  readonly threat_assessment: ThreatAssessment | null;
  readonly threat_intelligence?: ThreatIntelligenceBundle | null;
  readonly summary: string | null;
}

export interface ReportData {
  readonly id: string;
  readonly title: string;
  readonly report_type: 'pdf';
  readonly generated_at: string;
  readonly website_scan: ReportWebsiteScanData | null;
  readonly email_scan: ReportEmailScanData | null;
  readonly password_scan: ReportPasswordScanData | null;
  readonly log_scan: ReportLogScanData | null;
  readonly port_scan: ReportPortScanData | null;
  readonly summary: string | null;
  readonly findings?: readonly unknown[];
}

export interface Report {
  readonly id: string;
  readonly user_id: string;
  readonly title: string;
  readonly report_type: 'pdf';
  readonly storage_path: string;
  readonly report_data: ReportData | null;
  readonly created_at: string;
  readonly signed_url: string | null;
}

export interface ReportGenerateRequest {
  readonly title?: string;
}

export interface SqlScenario {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly example_payload: string;
  readonly vulnerable_explanation: string;
  readonly secure_explanation: string;
  readonly mitigation: string;
  readonly vulnerable_template: string;
  readonly secure_template: string;
}

export interface SqlRunRequest {
  readonly scenario: string;
  readonly payload: string;
}

export interface SqlResultSet {
  readonly rows: number;
  readonly columns: readonly string[];
  readonly data: readonly (readonly (string | number | null)[])[];
  readonly execution_status: 'ok' | 'rejected';
  readonly rejection_reason?: string;
}

export interface SqlExplanation {
  readonly what_happened: string;
  readonly why_vulnerable: string;
  readonly why_safe: string;
  readonly mitigation: string;
}

export interface SqlRunResult {
  readonly scenario: string;
  readonly input: string;
  readonly vulnerable_query: string;
  readonly safe_query: string;
  readonly vulnerable_result: SqlResultSet;
  readonly safe_result: SqlResultSet;
  readonly explanation: SqlExplanation;
  readonly sandbox: string;
}

export type PortState = 'open' | 'closed' | 'filtered';

export interface PortFinding {
  readonly port: number;
  readonly service: string;
  readonly state: PortState;
  readonly banner: string;
}

export type IPReputationState = 'unknown' | 'clean' | 'suspicious' | 'malicious' | 'unavailable';

export interface IPReputationResult {
  readonly ip: string;
  readonly reputation: IPReputationState;
  readonly confidence: string | null;
  readonly malicious: boolean;
  readonly suspicious: boolean;
  readonly reports: number;
  readonly country: string | null;
  readonly asn: number | null;
  readonly organization: string | null;
  readonly isp: string | null;
  readonly last_reported_at: string | null;
  readonly provider: string;
  readonly checked_at: string;
  readonly reason?: string | null;
}

export interface ThreatFactor {
  readonly type: string;
  readonly weight: number;
  readonly description: string;
}

export interface ThreatAssessment {
  readonly score: number;
  readonly level: 'low' | 'medium' | 'high' | 'critical';
  readonly confidence: 'high' | 'medium' | 'low';
  readonly factors: readonly ThreatFactor[];
  readonly explanation: string;
  readonly assessed_at: string;
}

export interface ProviderEvidence {
  readonly provider: string;
  readonly status: 'available' | 'unknown' | 'unavailable';
  readonly reputation: IPReputationState;
  readonly confidence: string | null;
  readonly threat_score?: number | null;
  readonly visitor_type?: number | null;
  readonly visitor_type_name?: string | null;
  readonly days_since_activity?: number | null;
  readonly last_seen?: string | null;
  readonly reason?: string | null;
  readonly checked_at: string;
  readonly malicious: boolean;
  readonly suspicious: boolean;
  readonly categories?: readonly string[];
  readonly evidence?: Record<string, unknown> | null;
  readonly raw?: Record<string, unknown> | null;
  readonly ip: string;
}

export interface ThreatIntelligenceBundle {
  readonly ip: string;
  readonly checked_at: string;
  readonly providers: readonly ProviderEvidence[];
  readonly available_providers: number;
  readonly sources_checked: number;
  readonly sources_available: number;
  readonly confidence: string;
  readonly summary: {
    readonly overall_reputation: IPReputationState;
    readonly evidence_confidence: string;
    readonly malicious: boolean;
    readonly suspicious: boolean;
    readonly sources_checked: number;
    readonly sources_available: number;
    readonly last_seen: string | null;
  };
}

export interface PortScanResult {
  readonly target: string;
  readonly resolved_ip: string;
  readonly scan_duration_ms: number;
  readonly ports_scanned: number;
  readonly open_ports: readonly PortFinding[];
  readonly closed_ports: number;
  readonly filtered_ports: number;
  readonly summary: string;
  readonly risk_level: 'low' | 'medium' | 'high' | 'critical';
  readonly ip_reputation?: IPReputationResult | null;
  readonly threat_assessment?: ThreatAssessment | null;
  readonly threat_intelligence?: ThreatIntelligenceBundle | null;
}

export interface PortScanRequest {
  readonly target: string;
  readonly ports?: readonly number[];
  readonly profile?: 'quick' | 'common';
}

export interface PortScanHistoryItem {
  readonly id: string;
  readonly target: string;
  readonly resolved_ip: string | null;
  readonly ports_scanned: number;
  readonly open_ports: readonly PortFinding[];
  readonly open_port_count: number;
  readonly scan_duration_ms: number | null;
  readonly risk_level: 'low' | 'medium' | 'high' | 'critical';
  readonly status: 'completed' | 'failed';
  readonly created_at: string;
  readonly ip_reputation?: IPReputationResult | null;
  readonly threat_assessment?: ThreatAssessment | null;
  readonly threat_intelligence?: ThreatIntelligenceBundle | null;
}

export interface PortScanHistoryMeta {
  readonly total: number;
  readonly page: number;
  readonly limit: number;
}

export interface PortScanHistoryResult {
  readonly scans: readonly PortScanHistoryItem[];
  readonly meta: PortScanHistoryMeta;
}

export interface PortScanDetail {
  readonly id: string;
  readonly target: string;
  readonly resolved_ip: string | null;
  readonly ports_scanned: number;
  readonly open_ports: readonly PortFinding[];
  readonly open_port_count: number;
  readonly closed_port_count: number;
  readonly filtered_port_count: number;
  readonly scan_duration_ms: number | null;
  readonly risk_level: 'low' | 'medium' | 'high' | 'critical';
  readonly status: 'completed' | 'failed';
  readonly created_at: string;
  readonly ip_reputation?: IPReputationResult | null;
  readonly threat_assessment?: ThreatAssessment | null;
  readonly threat_intelligence?: ThreatIntelligenceBundle | null;
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  evidence?: string;
  explanation: string;
  remediation: string;
}

export interface AnalysisReport {
  target_url: string;
  validated_ip: string;
  findings: Finding[];
  scan_metadata: Record<string, string>;
}

export interface HealthStatus {
  status: string;
}

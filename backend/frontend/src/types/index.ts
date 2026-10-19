export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  evidence?: string;
  explanation: string;
  remediation: string;
}

/** Extra scan details. Every field is optional: the backend only sends what it observed. */
export interface ScanMetadata {
  status?: string;
  /** Set when some checks were skipped, e.g. because the certificate failed verification. */
  note?: string;
  tls_version?: string;
  tls_cipher?: string;
  cert_subject?: string;
  cert_issuer?: string;
  cert_valid_until?: string;
  cert_days_remaining?: string;
}

export interface AnalysisReport {
  target_url: string;
  /** The IP address the backend actually connected to (validated as public). */
  validated_ip: string;
  findings: Finding[];
  scan_metadata: ScanMetadata;
}

export interface HealthStatus {
  status: string;
}

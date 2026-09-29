export type Verdict = "phishing" | "suspicious" | "legitimate";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  explanation: string;
  evidence: string[];
  weight: number;
}

export interface Address {
  display: string;
  email: string;
  domain: string;
  local: string;
}

export interface Report {
  verdict: Verdict;
  score: number;
  thresholds: { suspicious: number; phishing: number };
  summary: string;
  recommended_action: string;
  message: {
    subject?: string;
    date?: string;
    from?: Address | null;
    reply_to?: Address[];
    return_path?: string;
  };
  authentication: {
    authserv_id?: string;
    header_trusted?: boolean;
    spf?: string | null;
    dkim?: string | null;
    dmarc?: string | null;
    aligned?: boolean;
    mailfrom_domain?: string;
    dkim_signatures?: { result: string; domain: string }[];
  };
  identity: { sender_trusted: boolean; reply_to_mismatch: boolean };
  links: { url: string; host: string; scheme: string; source: string; visible_text: string; issues: string[] }[];
  attachments: { filename: string; content_type: string; size: number; magic: string }[];
  findings: Finding[];
  notes: Finding[];
}

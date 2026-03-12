/* ── Backend API types ──────────────────────────────────────────── */

export interface ApiAlert {
  id: number;
  created_at: string;
  severity: string;
  title: string;
  summary: string;
  analysis: string;
  mitigations: ApiMitigation[];
  affected_devices: string[];
  related_logs: string[];
  status: string;
  resolved_at: string | null;
}

export interface ApiMitigation {
  description: string;
  command: string;
  risk: string;
}

export interface ApiDevice {
  id: number;
  ip: string;
  hostname: string | null;
  vendor: string;
  device_type: string;
  first_seen: string;
  last_seen: string;
}

export interface ApiLog {
  id: number;
  received_at: string;
  source_ip: string;
  vendor: string;
  device_type: string;
  facility: number;
  severity: number;
  raw_message: string;
  parsed_fields: Record<string, string>;
}

export interface ApiStats {
  total_logs: number;
  by_vendor: Record<string, number>;
  by_device: Record<string, number>;
}

export interface ApiChatResponse {
  reply: string;
  session_id: string;
}

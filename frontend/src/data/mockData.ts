/* ── Mock / seed data for the SOC dashboard ─────────────────────── */

export type Severity = "low" | "medium" | "high" | "critical";
export type ThreatAction = "block" | "investigate" | "ignore";

export interface LogEntry {
  id: number;
  timestamp: string;
  srcIp: string;
  eventType: string;
  severity: Severity;
  aiInsight: string;
}

export interface TrafficPoint {
  time: string;
  inbound: number;
  outbound: number;
}

export interface SparkPoint {
  v: number;
}

export interface ThreatDistributionItem {
  name: string;
  value: number;
  fill: string;
}

export interface ActionHistoryItem {
  id: number;
  time: string;
  action: string;
  context: string;
}

export interface ThreatInfo {
  id: number;
  description: string;
  ip: string;
}

export interface Metrics {
  totalTraffic: number;
  blockedThreats: number;
  activeAnomalies: number;
  aiConfidence: number;
}

export interface Sparklines {
  traffic: SparkPoint[];
  blocked: SparkPoint[];
  anomalies: SparkPoint[];
  confidence: SparkPoint[];
}

export interface TextMessage {
  id: number;
  role: "user" | "assistant";
  type: "text";
  content: string;
}

export interface ThreatMessage {
  id: number;
  role: "user" | "assistant";
  type: "threat";
  content: string;
  threat: ThreatInfo;
  onAction: (action: ThreatAction, threat: ThreatInfo) => void;
}

export type ChatMessage = TextMessage | ThreatMessage;

/* ── Constants ───────────────────────────────────────────────────── */

const IPS: string[] = [
  "192.168.1.105", "10.0.0.34", "172.16.0.88", "45.33.32.156",
  "203.0.113.42", "198.51.100.7", "91.198.174.192", "104.26.10.78",
  "185.220.101.1", "23.129.64.100", "77.247.181.163", "162.247.74.27",
];

const EVENT_TYPES: string[] = [
  "DDoS Attempt", "Port Scan", "Brute Force SSH", "SQL Injection",
  "XSS Probe", "DNS Tunnelling", "Data Exfiltration", "Normal Traffic",
  "TLS Handshake Fail", "ICMP Flood", "ARP Spoofing", "Privilege Escalation",
];

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

const AI_INSIGHTS: string[] = [
  "Traffic pattern matches known botnet C2 signature.",
  "Anomalous volume spike — 4× baseline for this time window.",
  "Source IP flagged in 3 threat-intel feeds.",
  "Repeated failed auth attempts — credential stuffing likely.",
  "Payload contains encoded SQL — injection attempt.",
  "DNS query length exceeds normal — possible data exfiltration.",
  "Benign — matches expected CDN traffic pattern.",
  "Rate anomaly detected; correlating with geo-IP data.",
  "SYN flood pattern: high SYN, zero ACK.",
  "Encrypted payload on non-standard port — investigating.",
];

/* ── Utility functions ───────────────────────────────────────────── */

export function randomFrom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

export function randomBetween(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function generateLogEntry(id: number): LogEntry {
  const severity = randomFrom(SEVERITIES);
  return {
    id,
    timestamp: new Date().toISOString(),
    srcIp: randomFrom(IPS),
    eventType: severity === "low" ? "Normal Traffic" : randomFrom(EVENT_TYPES),
    severity,
    aiInsight: randomFrom(AI_INSIGHTS),
  };
}

export function seedTrafficData(points = 30): TrafficPoint[] {
  const now = Date.now();
  return Array.from({ length: points }, (_, i) => {
    const t = new Date(now - (points - i) * 60_000);
    return {
      time: t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      inbound: randomBetween(200, 600),
      outbound: randomBetween(100, 400),
    };
  });
}

export function seedSparkline(): SparkPoint[] {
  return Array.from({ length: 12 }, () => ({ v: randomBetween(30, 100) }));
}

/* ── Seed / static data ──────────────────────────────────────────── */

export const THREAT_DISTRIBUTION: ThreatDistributionItem[] = [
  { name: "DDoS",          value: 38, fill: "#dc2626" },
  { name: "SQL Injection", value: 22, fill: "#f59e0b" },
  { name: "Brute Force",   value: 18, fill: "#8b5cf6" },
  { name: "Port Scan",     value: 12, fill: "#3b82f6" },
  { name: "XSS",           value: 7,  fill: "#06b6d4" },
  { name: "Other",         value: 3,  fill: "#64748b" },
];

export const INITIAL_ACTION_HISTORY: ActionHistoryItem[] = [
  { id: 1, time: "14:32:07", action: "Blocked IP 185.220.101.1",   context: "Tor exit node — repeated port scan"  },
  { id: 2, time: "14:28:51", action: "Rate-limited 203.0.113.42",  context: "Holiday traffic anomaly"             },
  { id: 3, time: "14:15:22", action: "Triggered incident INC-20260307", context: "DDoS on port 443 confirmed"    },
  { id: 4, time: "13:59:03", action: "Escalated to L2 analyst",    context: "Ambiguous lateral movement"         },
];

export const INITIAL_CHAT: ChatMessage[] = [
  {
    id: 1,
    role: "assistant",
    type: "text",
    content:
      "Sentinel AI online. All systems nominal. I'm monitoring 12,847 flows/sec across 3 segments. What would you like to investigate?",
  },
];

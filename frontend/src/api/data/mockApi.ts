import type { ApiAlert, ApiDevice, ApiLog, ApiStats } from "@/api/types";

export const MOCK_DEVICES: ApiDevice[] = [
  { id: 1, ip: "10.0.0.1",       hostname: "FGT-SOCrates",  vendor: "Fortinet",  device_type: "FortiGate Firewall", first_seen: "2026-03-12 10:00:00", last_seen: "2026-03-12 18:30:00" },
  { id: 2, ip: "10.0.0.2",       hostname: "SW-Core-01",    vendor: "Cisco",     device_type: "Cisco IOS Switch",   first_seen: "2026-03-12 10:05:00", last_seen: "2026-03-12 18:28:00" },
  { id: 3, ip: "10.0.0.3",       hostname: "SRV-WEB-01",    vendor: "Linux",     device_type: "Linux Server",       first_seen: "2026-03-12 10:10:00", last_seen: "2026-03-12 18:25:00" },
  { id: 4, ip: "192.168.1.100",  hostname: "WS-Admin-01",   vendor: "Linux",     device_type: "Linux Workstation",  first_seen: "2026-03-12 12:00:00", last_seen: "2026-03-12 18:20:00" },
  { id: 5, ip: "172.16.0.10",    hostname: "DB-Primary",    vendor: "Linux",     device_type: "Linux Server",       first_seen: "2026-03-12 10:00:00", last_seen: "2026-03-12 18:15:00" },
];

export const MOCK_STATS: ApiStats = {
  total_logs: 1284,
  by_vendor: { Fortinet: 890, Cisco: 245, Linux: 149 },
  by_device: { "10.0.0.1": 890, "10.0.0.2": 245, "10.0.0.3": 100, "192.168.1.100": 30, "172.16.0.10": 19 },
};

const ts = () => new Date(Date.now() - Math.random() * 3600000).toISOString().replace("T", " ").slice(0, 19);

export const MOCK_ALERTS: ApiAlert[] = [
  {
    id: 1, created_at: "2026-03-12 13:22:57", severity: "high",
    title: "Widespread Internal Hosts Probing Multiple Services",
    summary: "Multiple denied connections to FTP, SMB, IMAPS, HTTPS, DNS from various internal IPs.",
    analysis: "The FortiGate firewall is blocking short connection bursts from many different internal IPs to a broad range of services. The broad spread of sources across multiple internal segments indicates coordinated or common-malware behavior.",
    mitigations: [
      { description: "Validate whether any authorized scanning is scheduled.", command: "N/A", risk: "low" },
      { description: "Tighten outbound access control policies on FortiGate.", command: "config firewall policy ...", risk: "medium" },
    ],
    affected_devices: ["10.0.13.76", "10.0.80.159", "192.168.61.115", "172.16.163.181"],
    related_logs: ["Fortinet/127.0.0.1 level=warning srcport=53089 ..."],
    status: "open", resolved_at: null,
  },
  {
    id: 2, created_at: "2026-03-12 13:23:35", severity: "high",
    title: "Blocked Botnet C2 Communications via IRC/SSH",
    summary: "Botnet-related traffic detected and blocked — attempted communication with known C2 infrastructure.",
    analysis: "Two internal hosts attempted to reach known C2 IPs using IRC semantics over HTTP/SSH channels. The high correlation score indicates confidence these are botnet-related destinations.",
    mitigations: [
      { description: "Isolate affected hosts from the network.", command: "N/A", risk: "low" },
      { description: "Confirm FortiGate C2 blocking policies.", command: "config firewall address ...", risk: "low" },
    ],
    affected_devices: ["10.0.76.175", "10.0.226.188"],
    related_logs: ["Fortinet/127.0.0.1 utmevent=botnet level=warning ..."],
    status: "open", resolved_at: null,
  },
  {
    id: 3, created_at: "2026-03-12 14:10:12", severity: "medium",
    title: "HTTPS Web Application Brute-force (Blocked)",
    summary: "WAF policy detected and blocked a brute-force attack against HTTPS service on 172.16.189.106:8443.",
    analysis: "External attacker trying many logins or requests against a web application. Application-level authentication being targeted.",
    mitigations: [
      { description: "Enable account lockout on the web application.", command: "N/A", risk: "low" },
    ],
    affected_devices: ["172.16.189.106"],
    related_logs: ["Fortinet/127.0.0.1 utmevent=waf level=warning ..."],
    status: "acknowledged", resolved_at: null,
  },
];

function randomParsedFields(): Record<string, string> {
  const actions = ["deny", "allow", "close", "server-rst"];
  const services = ["HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMB", "IMAPS"];
  const srcIps = ["10.0.13.76", "192.168.61.115", "172.16.163.181", "10.0.205.129", "10.0.53.9"];
  const dstIps = ["198.51.150.144", "203.0.108.109", "185.220.249.242", "10.0.1.58"];
  const pick = <T>(a: T[]) => a[Math.floor(Math.random() * a.length)];
  return {
    date: "2026-03-12",
    time: `${String(Math.floor(Math.random() * 24)).padStart(2, "0")}:${String(Math.floor(Math.random() * 60)).padStart(2, "0")}:${String(Math.floor(Math.random() * 60)).padStart(2, "0")}`,
    srcip: pick(srcIps),
    dstip: pick(dstIps),
    srcport: String(49152 + Math.floor(Math.random() * 16384)),
    dstport: String([21, 22, 53, 80, 443, 445, 993, 8080][Math.floor(Math.random() * 8)]),
    action: pick(actions),
    service: pick(services),
    proto: "6",
    level: Math.random() > 0.6 ? "warning" : "notice",
    devname: "FGT-SOCrates",
    policyname: pick(["default-deny", "Allow-Outbound-Web", "Rate-Limit-HTTP", "Monitor-Internal-Lateral"]),
    sentbyte: String(Math.floor(Math.random() * 10000)),
    rcvdbyte: String(Math.floor(Math.random() * 5000)),
  };
}

export function generateMockLogs(count: number): ApiLog[] {
  return Array.from({ length: count }, (_, i) => ({
    id: 1000 - i,
    received_at: ts(),
    source_ip: MOCK_DEVICES[Math.floor(Math.random() * MOCK_DEVICES.length)].ip,
    vendor: ["Fortinet", "Cisco", "Linux"][Math.floor(Math.random() * 3)],
    device_type: "FortiGate Firewall",
    facility: 16,
    severity: Math.random() > 0.6 ? 4 : 6,
    raw_message: "<134>firewall-sim: date=2026-03-12 ...",
    parsed_fields: randomParsedFields(),
  }));
}

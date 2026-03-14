import { useState, useMemo } from "react";
import { Network, MonitorDot, ChevronRight } from "lucide-react";
import { useDevices, useDeviceLogs } from "../hooks/useApiData";
import type { ApiDevice, ApiLog } from "../api/types";

/* Node layout helpers */
const VENDOR_COLORS: Record<string, string> = {
  Fortinet: "#dc2626",
  Cisco:    "#2563eb",
  Linux:    "#16a34a",
  Windows:  "#7c3aed",
  "Palo Alto": "#ea580c",
};

function vendorColor(vendor: string): string {
  return VENDOR_COLORS[vendor] ?? "#6b7280";
}

function pickFirst(...vals: Array<string | undefined | null>): string | null {
  for (const v of vals) {
    if (typeof v === "string" && v.trim()) return v;
  }
  return null;
}

function extractFlowFields(log: ApiLog): { action: string; service: string; dstip: string } {
  const pf = log.parsed_fields ?? {};
  const msg = (pf.message ?? log.raw_message ?? "") as string;

  const arrow = msg.match(/\b(\d+\.\d+\.\d+\.\d+)(?:\([^)]*\))?\s*->\s*(\d+\.\d+\.\d+\.\d+)\b/);
  const dstFromMsg = arrow?.[2] ?? null;

  const action = pickFirst(
    pf.action,
    pf.utmaction,
    pf.disposition,
    msg.toLowerCase().includes("heartbeat") ? "heartbeat" : undefined,
    pf.mnemonic,
    pf.process,
  ) ?? "—";

  const service = pickFirst(
    pf.service,
    pf.app,
    pf.proto,
    msg.toLowerCase().includes("heartbeat") ? "ha" : undefined,
  ) ?? "—";

  const dstip = pickFirst(
    pf.dstip,
    pf.dst,
    pf.destination,
    pf.to,
    dstFromMsg,
  ) ?? "—";

  return { action, service, dstip };
}

interface NodePos {
  device: ApiDevice;
  x: number;
  y: number;
}

function layoutNodes(devices: ApiDevice[], width: number, height: number): NodePos[] {
  if (devices.length === 0) return [];
  const cx = width / 2;
  const cy = height / 2;
  if (devices.length === 1) return [{ device: devices[0], x: cx, y: cy }];

  const radius = Math.min(width, height) * 0.35;
  return devices.map((device, i) => {
    const angle = (2 * Math.PI * i) / devices.length - Math.PI / 2;
    return {
      device,
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    };
  });
}

/* Network Map SVG */
interface MapProps {
  devices: ApiDevice[];
  selected: string | null;
  onSelect: (ip: string) => void;
}

function NetworkMap({ devices, selected, onSelect }: MapProps) {
  const W = 700;
  const H = 420;
  const nodes = useMemo(() => layoutNodes(devices, W, H), [devices]);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full">
      {/* Connection lines (all-to-all for simplicity) */}
      {nodes.map((a, i) =>
        nodes.slice(i + 1).map((b) => (
          <line
            key={`${a.device.ip}-${b.device.ip}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke="#e5e7eb"
            strokeWidth={1.5}
          />
        )),
      )}

      {/* Nodes */}
      {nodes.map(({ device, x, y }) => {
        const isSelected = device.ip === selected;
        const fill = vendorColor(device.vendor);
        return (
          <g
            key={device.ip}
            className="cursor-pointer"
            onClick={() => onSelect(device.ip)}
          >
            {/* Pulse ring when selected */}
            {isSelected && (
              <circle cx={x} cy={y} r={30} fill="none" stroke={fill} strokeWidth={2} opacity={0.3}>
                <animate attributeName="r" from="24" to="36" dur="1.2s" repeatCount="indefinite" />
                <animate attributeName="opacity" from="0.4" to="0" dur="1.2s" repeatCount="indefinite" />
              </circle>
            )}
            <circle
              cx={x}
              cy={y}
              r={22}
              fill={isSelected ? fill : "white"}
              stroke={fill}
              strokeWidth={isSelected ? 3 : 2}
            />
            <text
              x={x}
              y={y + 1}
              textAnchor="middle"
              dominantBaseline="central"
              className="pointer-events-none select-none text-[10px] font-bold"
              fill={isSelected ? "white" : fill}
            >
              {device.hostname ? device.hostname.slice(0, 6) : device.ip.split(".").pop()}
            </text>
            {/* Label below */}
            <text
              x={x}
              y={y + 36}
              textAnchor="middle"
              className="pointer-events-none select-none text-[9px]"
              fill="#6b7280"
            >
              {device.ip}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/* Device Log Table */
function DeviceLogTable({ logs, loading }: { logs: ApiLog[]; loading: boolean }) {
  if (loading) return <p className="p-4 text-sm text-gray-400">Loading logs...</p>;
  if (logs.length === 0) return <p className="p-4 text-sm text-gray-400">No logs for this device.</p>;

  return (
    <div className="max-h-[300px] overflow-y-auto">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-white">
          <tr className="border-b border-gray-200 text-left text-gray-500">
            <th className="px-4 py-2 font-medium">Time</th>
            <th className="px-3 py-2 font-medium">Vendor</th>
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">Action</th>
            <th className="px-3 py-2 font-medium">Service</th>
            <th className="px-3 py-2 font-medium">Dst IP</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => {
            const flow = extractFlowFields(log);
            return (
              <tr key={log.id} className="border-b border-gray-100 hover:bg-gray-50">
                <td className="whitespace-nowrap px-4 py-2 font-mono text-gray-500">{log.received_at}</td>
                <td className="px-3 py-2">{log.vendor}</td>
                <td className="px-3 py-2">
                  <span className={`inline-flex rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${log.severity <= 3 ? "bg-red-100 text-red-700" : log.severity <= 4 ? "bg-amber-100 text-amber-700" : "bg-green-100 text-green-700"}`}>
                    {log.severity <= 3 ? "high" : log.severity <= 4 ? "medium" : "low"}
                  </span>
                </td>
                <td className="px-3 py-2 text-gray-700">{flow.action}</td>
                <td className="px-3 py-2 text-gray-700">{flow.service}</td>
                <td className="px-3 py-2 font-mono text-gray-700">{flow.dstip}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* Main Devices View */
export default function DevicesView() {
  const { devices, loading } = useDevices();
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const { logs: deviceLogs, loading: logsLoading } = useDeviceLogs(selectedIp);

  const selectedDevice = devices.find((d) => d.ip === selectedIp);

  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <p className="text-gray-400">Loading devices...</p>
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
      {/* Network map card */}
      <div className="rounded-lg border border-black bg-white p-5">
        <div className="mb-3 flex items-center gap-2">
          <Network className="h-4 w-4 text-blue-600" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-500">
            Network Topology
          </h3>
          <span className="ml-auto text-xs text-gray-400">{devices.length} devices</span>
        </div>
        <div className="flex aspect-[5/3] items-center justify-center">
          {devices.length === 0 ? (
            <p className="text-sm text-gray-400">No devices discovered yet.</p>
          ) : (
            <NetworkMap devices={devices} selected={selectedIp} onSelect={setSelectedIp} />
          )}
        </div>
      </div>

      {/* Device detail + logs */}
      {selectedDevice && (
        <div className="rounded-lg border border-black bg-white">
          <div className="flex items-center gap-2 border-b border-gray-200 px-5 py-3">
            <MonitorDot className="h-4 w-4" style={{ color: vendorColor(selectedDevice.vendor) }} />
            <h3 className="text-sm font-semibold text-gray-800">
              {selectedDevice.hostname ?? selectedDevice.ip}
            </h3>
            <ChevronRight className="h-3 w-3 text-gray-400" />
            <span className="text-xs text-gray-500">{selectedDevice.ip}</span>
            <span className="ml-2 rounded bg-gray-100 px-2 py-0.5 text-[10px] font-medium text-gray-600">
              {selectedDevice.vendor} / {selectedDevice.device_type}
            </span>
            <span className="ml-auto text-[10px] text-gray-400">
              Last seen {selectedDevice.last_seen}
            </span>
          </div>
          <DeviceLogTable logs={deviceLogs} loading={logsLoading} />
        </div>
      )}
    </div>
  );
}

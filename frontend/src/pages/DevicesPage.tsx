import { useState, useMemo } from "react";
import { Network, MonitorDot, ChevronRight } from "lucide-react";
import { useDevices, useDeviceLogs } from "@/hooks/useApiData";
import { getVendorColor } from "@/utils/colors";
import type { ApiDevice, ApiLog } from "@/api/types";

/* Node layout helpers */

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
  
  // Calculate grid dimensions to make it roughly square
  const cols = Math.ceil(Math.sqrt(devices.length));
  const rows = Math.ceil(devices.length / cols);
  
  // Padding from the edges of the SVG canvas
  const paddingX = 80;
  const paddingY = 80;
  
  // Usable area for the grid
  const usableWidth = width - (paddingX * 2);
  const usableHeight = height - (paddingY * 2);

  // Spacing between columns and rows
  const spacingX = cols > 1 ? usableWidth / (cols - 1) : 0;
  const spacingY = rows > 1 ? usableHeight / (rows - 1) : 0;
  
  // If only 1 node, center it
  if (devices.length === 1) {
    return [{ device: devices[0], x: width / 2, y: height / 2 }];
  }

  return devices.map((device, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);

    // X coordinates expand out, centered if cols == 1
    const x = cols > 1 
      ? paddingX + col * spacingX 
      : width / 2;

    // Y coordinates expand down, centered if rows == 1
    const y = rows > 1 
      ? paddingY + row * spacingY 
      : height / 2;

    return {
      device,
      x,
      y,
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
    <svg 
      viewBox={`0 0 ${W} ${H}`} 
      className="h-full w-full"
      onClick={() => onSelect("")} // clicking the canvas clears selection
    >
      {/* Nodes */}
      {nodes.map(({ device, x, y }) => {
        const isSelected = device.ip === selected;
        const fill = getVendorColor(device.vendor);
        return (
          <g
            key={device.ip}
            className="cursor-pointer transition-transform duration-200"
            style={{ 
              transform: isSelected ? `translate(${x}px, ${y}px) scale(1.05)` : `translate(${x}px, ${y}px)`,
              transformOrigin: "0 0" 
            }}
            onClick={(e) => {
              e.stopPropagation(); // prevent canvas click from clearing selection
              onSelect(device.ip);
            }}
          >
            {/* Box shadow effect */}
            <rect
              x={-50}
              y={-22}
              width={100}
              height={44}
              rx={8}
              fill="#000"
              opacity={isSelected ? 0.15 : 0.05}
              transform="translate(2, 4)"
            />
            {/* Main rect */}
            <rect
              x={-50}
              y={-22}
              width={100}
              height={44}
              rx={8}
              fill="white"
              stroke={isSelected ? fill : "#e2e8f0"}
              strokeWidth={isSelected ? 2 : 1}
            />
            {/* Vendor accent line */}
            <rect
              x={-50}
              y={-22}
              width={6}
              height={44}
              rx={8}
              fill={fill}
            />
            {/* Fix straight edge on right side of accent line to merge cleanly */}
            <rect
              x={-47}
              y={-22}
              width={3}
              height={44}
              fill={fill}
            />
            
            {/* Hostname */}
            <text
              x={-34}
              y={-4}
              textAnchor="start"
              className="pointer-events-none select-none text-[11px] font-bold"
              fill="#1e293b"
            >
              {device.hostname ? device.hostname.slice(0, 10) : device.ip.split(".").pop()}
            </text>
            
            {/* IP Address inside node */}
            <text
              x={-34}
              y={10}
              textAnchor="start"
              className="pointer-events-none select-none text-[9px] font-mono"
              fill="#64748b"
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
export default function DevicesPage() {
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
      <div className="rounded-xl border-2 border-gray-700 bg-white p-5">
        <div className="mb-3 flex items-center gap-2">
          <Network className="h-5 w-5 text-[#5271ff]" />
          <h3 className="text-md font-unica font-semibold uppercase tracking-wider text-gray-700">
            Network Topology
          </h3>
        </div>
        <div
          className="flex aspect-[6/3] items-center justify-center rounded-lg border-2 border-gray-300 bg-slate-50"
          style={{
            backgroundImage:
              "linear-gradient(to right, rgba(148,163,184,0.2) 1px, transparent 1px), linear-gradient(to bottom, rgba(148,163,184,0.2) 1px, transparent 1px)",
            backgroundSize: "28px 28px",
          }}
        >
          {devices.length === 0 ? (
            <p className="text-sm text-gray-400">No devices discovered yet.</p>
          ) : (
            <NetworkMap devices={devices} selected={selectedIp} onSelect={setSelectedIp} />
          )}
        </div>
      </div>

      {/* Device detail + logs */}
      {selectedDevice && (
        <div className="rounded-xl border-2 border-gray-700 bg-white">
          <div className="flex items-center gap-2 border-b border-gray-200 px-5 py-3">
            <MonitorDot className="h-4 w-4" style={{ color: getVendorColor(selectedDevice.vendor) }} />
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

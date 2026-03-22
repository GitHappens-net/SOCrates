import { useState, useMemo, useEffect, useRef } from "react";
import { Network, MonitorDot, ChevronRight } from "lucide-react";
import { useLocation } from "react-router-dom";
import { useDevices, useDeviceLogs } from "@/hooks/useApiData";
import { getVendorColor } from "@/utils/colors";
import type { ApiDevice, ApiLog } from "@/api/types";

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
function DeviceLogTable({ logs, loading, limit, setLimit }: { logs: ApiLog[]; loading: boolean, limit: number, setLimit: (limit: number) => void }) {
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [sortOrder, setSortOrder] = useState<"desc" | "asc">("desc");

  const filteredLogs = logs.filter((log) => {
    if (filterSeverity === "all") return true;
    const sevLabel = log.severity <= 3 ? "high" : log.severity <= 4 ? "medium" : "low";
    if (filterSeverity === "high-critical") return sevLabel === "high"; // Since high means <=3
    return sevLabel === filterSeverity;
  });

  const sortedLogs = [...filteredLogs].sort((a, b) => {
    const timeA = new Date(a.received_at).getTime();
    const timeB = new Date(b.received_at).getTime();
    if (sortOrder === "asc") return timeA - timeB;
    return timeB - timeA;
  });

  return (
    <div className="flex flex-col h-[500px]">
      <div className="flex flex-wrap items-center gap-4 border-b border-gray-200 px-4 py-2 text-xs text-gray-700 bg-gray-50 flex-none">
        <div className="flex items-center gap-1.5">
          <label htmlFor="severity-dev" className="font-medium">Severity:</label>
          <select
            id="severity-dev"
            className="rounded border border-gray-300 px-1 py-0.5 focus:border-gray-700 focus:outline-none"
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
          >
            <option value="all">All</option>
            <option value="high-critical">High / Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="flex items-center gap-1.5">
          <label htmlFor="limit-dev" className="font-medium">Show:</label>
          <select
            id="limit-dev"
            className="rounded border border-gray-300 px-1 py-0.5 focus:border-gray-700 focus:outline-none"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={50}>Last 50</option>
            <option value={100}>Last 100</option>
            <option value={200}>Last 200</option>
            <option value={500}>Last 500</option>
            <option value={1000}>Last 1000</option>
          </select>
        </div>

        <div className="flex items-center gap-1.5">
          <label htmlFor="sort-dev" className="font-medium">Order:</label>
          <select
            id="sort-dev"
            className="rounded border border-gray-300 px-1 py-0.5 focus:border-gray-700 focus:outline-none"
            value={sortOrder}
            onChange={(e) => setSortOrder(e.target.value as "desc" | "asc")}
          >
            <option value="desc">Newest First</option>
            <option value="asc">Oldest First</option>
          </select>
        </div>
        <span className="ml-auto font-medium text-gray-500">{loading ? "Loading..." : `${sortedLogs.length} matching`}</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {logs.length === 0 && !loading ? (
          <p className="p-4 text-sm text-gray-400">No logs for this device.</p>
        ) : (
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-white shadow-sm z-10">
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
            {sortedLogs.map((log) => {
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
        )}
      </div>
    </div>
  );
}

/* Main Devices View */
export default function DevicesPage() {
  const location = useLocation();
  const { devices, loading } = useDevices();
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [limit, setLimit] = useState<number>(200);
  const { logs: deviceLogs, loading: logsLoading } = useDeviceLogs(selectedIp, limit);
  const detailsRef = useRef<HTMLDivElement>(null);
  const hasScrolledRef = useRef(false);

  const selectedDevice = devices.find((d) => d.ip === selectedIp);

  // Sync with URL parameter
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const ip = params.get("ip");
    if (ip) {
      handleSelectDevice(ip);
    }
  }, [location.search, devices]);

  // Scroll to details on first visual selection
  useEffect(() => {
    if (selectedDevice && !hasScrolledRef.current && detailsRef.current) {
      // Small timeout to allow the element to render before scrolling
      setTimeout(() => {
        detailsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
        hasScrolledRef.current = true;
      }, 50);
    }
  }, [selectedDevice]);

  function handleSelectDevice(ip: string | null) {
    setSelectedIp(ip);
    window.dispatchEvent(new CustomEvent("CHAT_SET_TARGET", { detail: ip }));
    
    // Reset scroll if manually clicking a new device map node after the first automatically scrolled selection
    if (ip && ip !== selectedIp) {
      hasScrolledRef.current = false;
    }
  }

  // Clear target context on unmount or navigation
  useEffect(() => {
    return () => {
      window.dispatchEvent(new CustomEvent("CHAT_SET_TARGET", { detail: null }));
    };
  }, []);

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
      <div className="rounded-xl border-2 border-gray-700 bg-white p-5 pt-3">
        <div className="mb-3 flex items-center gap-2 flex-none">
          <Network className="h-5 w-5 text-[#5271ff]" />
          <h3 className="text-lg font-unica font-semibold uppercase tracking-wider text-gray-700">
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
            <NetworkMap devices={devices} selected={selectedIp} onSelect={handleSelectDevice} />
          )}
        </div>
      </div>

      {/* Device detail + logs */}
      {selectedDevice && (
        <div ref={detailsRef} className="rounded-xl border-2 border-gray-700 bg-white overflow-hidden flex flex-col scroll-mt-[60vh]">
          <div className="flex flex-wrap items-center gap-2 border-b border-gray-200 px-5 py-3 flex-none">
            <MonitorDot className="h-4 w-4" style={{ color: getVendorColor(selectedDevice.vendor) }} />
            <h3 className="text-sm font-semibold text-gray-800">
              {selectedDevice.hostname ?? selectedDevice.ip}
            </h3>
            <ChevronRight className="h-3 w-3 text-gray-400" />
            <span className="text-xs text-gray-500">{selectedDevice.ip}</span>
            <span className="ml-2 rounded bg-gray-100 px-2 py-0.5 text-[10px] font-medium text-gray-600">
              {selectedDevice.vendor} / {selectedDevice.device_type}
            </span>
            <span className="ml-auto text-[10px] text-gray-400 w-full sm:w-auto text-right">
              Last seen {selectedDevice.last_seen}
            </span>
          </div>
          <DeviceLogTable logs={deviceLogs} loading={logsLoading} limit={limit} setLimit={setLimit} />
        </div>
      )}
    </div>
  );
}

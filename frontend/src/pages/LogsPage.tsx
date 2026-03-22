import { useState, useEffect, useRef } from "react";
import { MonitorDot, ChevronDown, ChevronUp } from "lucide-react";
import { useLocation } from "react-router-dom";
import { useLogs, useStats } from "@/hooks/useApiData";
import type { ApiLog } from "@/api/types";

/* Severity helpers */
function sevLabel(n: number): string {
  if (n <= 2) return "critical";
  if (n <= 3) return "high";
  if (n <= 4) return "medium";
  return "low";
}

function sevClasses(n: number): string {
  if (n <= 2) return "bg-red-100 text-red-700 ring-red-400";
  if (n <= 3) return "bg-orange-100 text-orange-700 ring-orange-400";
  if (n <= 4) return "bg-amber-100 text-amber-700 ring-amber-400";
  return "bg-green-100 text-green-700 ring-green-400";
}

function pickFirst(...vals: Array<string | undefined | null>): string | null {
  for (const v of vals) {
    if (typeof v === "string" && v.trim()) return v;
  }
  return null;
}

function flowSummary(log: ApiLog): { action: string; service: string } {
  const pf = log.parsed_fields ?? {};
  const msg = (pf.message ?? log.raw_message ?? "") as string;

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

  return { action, service };
}

/* Expandable row */
function LogRow({ log }: { log: ApiLog }) {
  const [open, setOpen] = useState(false);
  const pf = log.parsed_fields ?? {};
  const flow = flowSummary(log);

  return (
    <>
      <tr
        className="cursor-pointer border-b border-gray-100 hover:bg-gray-50"
        onClick={() => setOpen((v) => !v)}
      >
        <td className="whitespace-nowrap px-5 py-2.5 font-mono text-gray-500">
          {log.received_at}
        </td>
        <td className="whitespace-nowrap px-3 py-2.5 font-mono text-gray-900">{log.source_ip}</td>
        <td className="px-3 py-2.5 text-gray-700">{log.vendor}</td>
        <td className="px-3 py-2.5">
          <span
            className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ${sevClasses(log.severity)}`}
          >
            {sevLabel(log.severity)}
          </span>
        </td>
        <td className="px-3 py-2.5 text-gray-700">{flow.action}</td>
        <td className="px-3 py-2.5 text-gray-700">{flow.service}</td>
        <td className="px-3 py-2.5 text-center">
          {open ? (
            <ChevronUp className="mx-auto h-3.5 w-3.5 text-gray-400" />
          ) : (
            <ChevronDown className="mx-auto h-3.5 w-3.5 text-gray-400" />
          )}
        </td>
      </tr>
      {open && (
        <tr className="bg-gray-50">
          <td colSpan={7} className="px-5 py-3">
            <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-xs sm:grid-cols-4">
              {Object.entries(pf).map(([k, v]) => (
                <div key={k}>
                  <span className="font-semibold text-gray-500">{k}:</span>{" "}
                  <span className="text-gray-800">{v}</span>
                </div>
              ))}
            </div>
            <p className="mt-2 rounded bg-gray-100 px-3 py-2 font-mono text-[10px] text-gray-600 break-all">
              {log.raw_message}
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

/* Main Logs View */
export default function LogsPage() {
  const location = useLocation();
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterVendor, setFilterVendor] = useState<string>("all");
  const [sortOrder, setSortOrder] = useState<"desc" | "asc">("desc");
  const [limit, setLimit] = useState<number>(200);

  const vendorSelectRef = useRef<HTMLSelectElement>(null);

  const { stats } = useStats();
  const availableVendors = stats ? Object.keys(stats.by_vendor).sort() : [];

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const sev = params.get("severity");
    if (sev) {
      setFilterSeverity(sev);
    }
    const vend = params.get("vendor");
    if (vend) {
      setFilterVendor(vend);
    }
    
    const focusParam = params.get("focus");
    if (focusParam === "vendor") {
      setTimeout(() => {
        vendorSelectRef.current?.focus();
      }, 100);
    }
  }, [location.search]);

  const { logs, loading } = useLogs(limit, 1000);

  // Filter logs
  const filteredLogs = logs.filter((log) => {
    if (filterVendor !== "all" && log.vendor.toLowerCase() !== filterVendor.toLowerCase()) return false;
    if (filterSeverity === "all") return true;
    if (filterSeverity === "high-critical") {
      return sevLabel(log.severity) === "high" || sevLabel(log.severity) === "critical";
    }
    return sevLabel(log.severity) === filterSeverity;
  });

  // Sort logs
  const sortedLogs = [...filteredLogs].sort((a, b) => {
    const timeA = new Date(a.received_at).getTime();
    const timeB = new Date(b.received_at).getTime();
    if (sortOrder === "asc") return timeA - timeB;
    return timeB - timeA;
  });

  return (
    <div className="flex flex-1 flex-col rounded-xl border-2 border-gray-700 bg-white">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-4 border-b border-gray-200 px-5 py-3">
        <div className="flex items-center gap-2">
          <MonitorDot className="h-5 w-5 text-[#5271ff]" />
          <h3 className="text-lg font-unica font-semibold uppercase tracking-wider text-gray-700">
            All Logs
          </h3>
        </div>

        <div className="ml-auto flex items-center gap-4 text-xs text-gray-700">
          <div className="flex items-center gap-1.5">
            <label htmlFor="vendor" className="font-medium">Vendor:</label>
            <select
              id="vendor"
              ref={vendorSelectRef}
              className="rounded-lg border-2 border-gray-300 px-2 py-1 focus:border-gray-700 focus:outline-none capitalize focus:ring-2 focus:ring-[#5271ff]/50"
              value={filterVendor}
              onChange={(e) => setFilterVendor(e.target.value)}
            >
              <option value="all">All Vendors</option>
              {availableVendors.map((v) => (
                <option key={v} value={v.toLowerCase()}>{v}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <label htmlFor="severity" className="font-medium">Severity:</label>
            <select
              id="severity"
              className="rounded-lg border-2 border-gray-300 px-2 py-1 focus:border-gray-700 focus:outline-none"
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
            >
              <option value="all">All</option>
              <option value="high-critical">High / Critical</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <label htmlFor="limit" className="font-medium">Show:</label>
            <select
              id="limit"
              className="rounded-lg border-2 border-gray-300 px-2 py-1 focus:border-gray-700 focus:outline-none"
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
            <label htmlFor="sort" className="font-medium">Order:</label>
            <select
              id="sort"
              className="rounded-lg border-2 border-gray-300 px-2 py-1 focus:border-gray-700 focus:outline-none"
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as "desc" | "asc")}
            >
              <option value="desc">Newest First (Desc)</option>
              <option value="asc">Oldest First (Asc)</option>
            </select>
          </div>

          <span className="flex items-center gap-1.5 ml-4 font-bold text-green-700">
            <span className={`h-3 w-3 rounded-full ${loading ? 'bg-amber-500' : 'bg-green-600'}`} />
            {loading ? "Loading..." : `${sortedLogs.length} logs`}
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-white">
            <tr className="border-b border-gray-200 text-left text-gray-500 shadow-sm">
              <th className="px-5 py-2.5 font-medium">Timestamp</th>
              <th className="px-3 py-2.5 font-medium">Source IP</th>
              <th className="px-3 py-2.5 font-medium">Vendor</th>
              <th className="px-3 py-2.5 font-medium">Severity</th>
              <th className="px-3 py-2.5 font-medium">Action</th>
              <th className="px-3 py-2.5 font-medium">Service</th>
              <th className="w-8 px-3 py-2.5"></th>
            </tr>
          </thead>
          <tbody>
            {sortedLogs.map((log) => (
              <LogRow key={log.id} log={log} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

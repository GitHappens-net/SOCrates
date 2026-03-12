import { useState } from "react";
import { MonitorDot, ChevronDown, ChevronUp } from "lucide-react";
import { useLogs } from "../hooks/useApiData";
import type { ApiLog } from "../types";

/* ── Severity helpers ────────────────────────────────────────────── */

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

/* ── Expandable row ──────────────────────────────────────────────── */

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

/* ── Main Logs View ──────────────────────────────────────────────── */

export default function LogsView() {
  const { logs, loading } = useLogs(200, 5000);

  return (
    <div className="flex flex-1 flex-col rounded-lg border border-black bg-white">
      {/* Title */}
      <div className="flex items-center gap-2 border-b border-gray-200 px-5 py-3">
        <MonitorDot className="h-4 w-4 text-blue-600" />
        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-500">
          All Logs
        </h3>
        <span className="ml-auto flex items-center gap-1.5 text-xs text-green-600">
          <span className="h-2 w-2 rounded-full bg-green-600" />
          {loading ? "Loading..." : `${logs.length} logs`}
        </span>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-white">
            <tr className="border-b border-gray-200 text-left text-gray-500">
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
            {logs.map((log) => (
              <LogRow key={log.id} log={log} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

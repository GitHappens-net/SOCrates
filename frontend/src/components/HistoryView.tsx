import { useState } from "react";
import {
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertTriangle,
  XCircle,
} from "lucide-react";
import { useAlerts } from "../hooks/useApiData";
import { patchAlertStatus } from "../api/client";
import type { ApiAlert } from "../types";

/* ── Severity badge ──────────────────────────────────────────────── */

const SEV_CLASSES: Record<string, string> = {
  critical: "bg-red-100 text-red-700 ring-red-400",
  high:     "bg-orange-100 text-orange-700 ring-orange-400",
  medium:   "bg-amber-100 text-amber-700 ring-amber-400",
  low:      "bg-green-100 text-green-700 ring-green-400",
};

const STATUS_ICON: Record<string, typeof CheckCircle2> = {
  open:         AlertTriangle,
  acknowledged: ShieldAlert,
  resolved:     CheckCircle2,
  dismissed:    XCircle,
};

/* ── Alert card (expandable) ─────────────────────────────────────── */

function AlertCard({ alert, onStatusChange }: { alert: ApiAlert; onStatusChange: () => void }) {
  const [open, setOpen] = useState(false);
  const StatusIcon = STATUS_ICON[alert.status] ?? AlertTriangle;

  async function changeStatus(status: string) {
    await patchAlertStatus(alert.id, status);
    onStatusChange();
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white">
      {/* Header row */}
      <button
        className="flex w-full items-center gap-3 px-5 py-3 text-left hover:bg-gray-50"
        onClick={() => setOpen((v) => !v)}
      >
        <StatusIcon
          className={`h-5 w-5 shrink-0 ${
            alert.severity === "critical" || alert.severity === "high"
              ? "text-red-600"
              : alert.severity === "medium"
              ? "text-amber-600"
              : "text-green-600"
          }`}
        />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-gray-900">{alert.title}</p>
          <p className="truncate text-xs text-gray-500">{alert.summary}</p>
        </div>
        <span
          className={`shrink-0 rounded px-2 py-0.5 text-[10px] font-bold uppercase ring-1 ${SEV_CLASSES[alert.severity] ?? SEV_CLASSES.medium}`}
        >
          {alert.severity}
        </span>
        <span className="shrink-0 rounded bg-gray-100 px-2 py-0.5 text-[10px] font-medium text-gray-600">
          {alert.status}
        </span>
        <span className="shrink-0 text-[10px] text-gray-400">{alert.created_at}</span>
        {open ? (
          <ChevronUp className="h-4 w-4 shrink-0 text-gray-400" />
        ) : (
          <ChevronDown className="h-4 w-4 shrink-0 text-gray-400" />
        )}
      </button>

      {/* Expand */}
      {open && (
        <div className="border-t border-gray-100 px-5 py-4">
          {/* Analysis */}
          <h4 className="mb-1 text-xs font-bold uppercase tracking-wider text-gray-500">AI Analysis</h4>
          <p className="mb-4 text-sm leading-relaxed text-gray-800 whitespace-pre-wrap">{alert.analysis}</p>

          {/* Mitigations */}
          {alert.mitigations.length > 0 && (
            <>
              <h4 className="mb-1 text-xs font-bold uppercase tracking-wider text-gray-500">Recommended Mitigations</h4>
              <ul className="mb-4 space-y-2">
                {alert.mitigations.map((m, i) => (
                  <li key={i} className="rounded border border-gray-200 bg-gray-50 px-3 py-2 text-xs">
                    <p className="font-medium text-gray-800">{m.description}</p>
                    {m.command !== "N/A" && (
                      <code className="mt-1 block rounded bg-gray-200 px-2 py-1 text-[10px] text-gray-700 break-all">
                        {m.command}
                      </code>
                    )}
                    <span className={`mt-1 inline-block rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${m.risk === "low" ? "bg-green-100 text-green-700" : m.risk === "medium" ? "bg-amber-100 text-amber-700" : "bg-red-100 text-red-700"}`}>
                      risk: {m.risk}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}

          {/* Affected devices */}
          {alert.affected_devices.length > 0 && (
            <div className="mb-4">
              <h4 className="mb-1 text-xs font-bold uppercase tracking-wider text-gray-500">Affected Devices</h4>
              <div className="flex flex-wrap gap-2">
                {alert.affected_devices.map((ip) => (
                  <span key={ip} className="rounded border bg-gray-100 px-2 py-0.5 font-mono text-[10px] text-gray-700">
                    {ip}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Status actions */}
          <div className="flex gap-2 border-t border-gray-100 pt-3">
            {alert.status !== "acknowledged" && (
              <button
                onClick={() => changeStatus("acknowledged")}
                className="rounded border border-blue-600 bg-blue-50 px-3 py-1.5 text-[11px] font-semibold text-blue-700 transition hover:bg-blue-100"
              >
                Acknowledge
              </button>
            )}
            {alert.status !== "resolved" && (
              <button
                onClick={() => changeStatus("resolved")}
                className="rounded border border-green-600 bg-green-50 px-3 py-1.5 text-[11px] font-semibold text-green-700 transition hover:bg-green-100"
              >
                Resolve
              </button>
            )}
            {alert.status !== "dismissed" && (
              <button
                onClick={() => changeStatus("dismissed")}
                className="rounded border border-gray-300 bg-gray-50 px-3 py-1.5 text-[11px] font-semibold text-gray-600 transition hover:bg-gray-100"
              >
                Dismiss
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Main History View ───────────────────────────────────────────── */

export default function HistoryView() {
  const { alerts, loading, reload } = useAlerts();
  const [filter, setFilter] = useState<string>("all");

  const filtered = filter === "all" ? alerts : alerts.filter((a) => a.status === filter);

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
      {/* Header bar */}
      <div className="flex items-center gap-3 rounded-lg border border-black bg-white px-5 py-3">
        <ShieldAlert className="h-4 w-4 text-red-600" />
        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-500">
          AI Analysis History
        </h3>
        <div className="ml-auto flex items-center gap-2">
          {["all", "open", "acknowledged", "resolved", "dismissed"].map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`rounded px-2.5 py-1 text-[11px] font-semibold capitalize transition ${
                filter === s
                  ? "bg-black text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <span className="text-xs text-gray-400">
          {loading ? "Loading..." : `${filtered.length} alerts`}
        </span>
      </div>

      {/* Alert cards */}
      <div className="space-y-3">
        {filtered.length === 0 && !loading && (
          <p className="py-10 text-center text-sm text-gray-400">No alerts found.</p>
        )}
        {filtered.map((alert) => (
          <AlertCard key={alert.id} alert={alert} onStatusChange={reload} />
        ))}
      </div>
    </div>
  );
}

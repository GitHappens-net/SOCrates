import { useState } from "react";
import { ShieldAlert, ChevronDown, ChevronUp, CheckCircle2, AlertTriangle, XCircle } from "lucide-react";
import { patchAlertStatus } from "@/api/client";
import type { ApiAlert } from "@/api/types";

const SEV_CLASSES: Record<string, string> = {
  critical: "bg-red-100 text-red-700 ring-red-400",
  high: "bg-orange-100 text-orange-700 ring-orange-400",
  medium: "bg-amber-100 text-amber-700 ring-amber-400",
  low: "bg-green-100 text-green-700 ring-green-400",
};

const STATUS_ICON: Record<string, typeof CheckCircle2> = {
  open: AlertTriangle,
  acknowledged: ShieldAlert,
  resolved: CheckCircle2,
  dismissed: XCircle,
};

interface HistoryAlertItemProps {
  alert: ApiAlert;
  onStatusChange: () => void;
}

export default function HistoryAlertItem({ alert, onStatusChange }: HistoryAlertItemProps) {
  const [open, setOpen] = useState(false);
  const StatusIcon = STATUS_ICON[alert.status] ?? AlertTriangle;

  async function changeStatus(status: string) {
    await patchAlertStatus(alert.id, status);
    onStatusChange();
  }

  return (
    <div className="rounded-xl border-2 border-gray-700 bg-white">
      <button
        className="flex w-full items-center gap-3 px-5 py-3 text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <StatusIcon
          className={`h-5 w-5 shrink-0 ${
            alert.severity === "critical" || alert.severity === "high"
              ? "text-red-600"
              : alert.severity === "medium"
              ? "text-orange-400"
              : "text-green-600"
          }`}
        />
        <div className="min-w-0 flex-1">
          <p className="truncate text-md font-semibold text-gray-900">{alert.title}</p>
          <p className="truncate text-xs text-gray-500">{alert.summary}</p>
        </div>
        <span className="shrink-0 rounded-full bg-gray-200 px-2 py-0.5 text-[12px] font-bold text-gray-700 font-unica">
          {alert.status}
        </span>
        <span className="shrink-0 text-[10px] text-gray-400">{alert.created_at}</span>
        {open ? (
          <ChevronUp className="h-4 w-4 shrink-0 text-gray-400" />
        ) : (
          <ChevronDown className="h-4 w-4 shrink-0 text-gray-400" />
        )}
      </button>

      {open && (
        <div className="border-t border-gray-100 px-5 py-4">
          <h4 className="mb-1 text-md font-unica font-bold uppercase tracking-wider text-gray-700">AI Analysis</h4>
          <p className="mb-4 whitespace-pre-wrap text-sm leading-relaxed text-gray-800">{alert.analysis}</p>

          {alert.mitigations.length > 0 && (
            <>
              <h4 className="mb-1 text-md font-unica font-bold uppercase tracking-wider text-gray-700">
                Recommended Mitigations
              </h4>
              <ul className="mb-4 space-y-2">
                {alert.mitigations.map((m, i) => (
                  <li key={i} className="rounded-xl border-2 border-gray-300 bg-gray-50 px-3 py-2 text-xs">
                    <p className="font-medium text-gray-800">{m.description}</p>
                    {m.command !== "N/A" && (
                      <code className="mt-1 block break-all rounded-lg bg-gray-200 px-2 py-1 text-[11px] text-gray-700">
                        {m.command}
                      </code>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}

          {alert.affected_devices.length > 0 && (
            <div className="mb-4">
              <h4 className="mb-1 text-md font-unica font-bold uppercase tracking-wider text-gray-700">Affected Devices</h4>
              <div className="flex flex-wrap gap-2">
                {alert.affected_devices.map((ip) => (
                  <span
                    key={ip}
                    className="rounded-full border-2 bg-gray-100 px-2 py-0.5 font-mono text-[11px] text-gray-700"
                  >
                    {ip}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="flex gap-2 border-t border-gray-300 pt-3">
            {alert.status !== "acknowledged" && (
              <button
                onClick={() => changeStatus("acknowledged")}
                className="rounded-full border-2 border-[#5271ff] bg-white hover:bg-blue-100 px-3 py-1.5 text-[12px] font-semibold text-[#5271ff]"
              >
                Acknowledge
              </button>
            )}
            {alert.status !== "resolved" && (
              <button
                onClick={() => changeStatus("resolved")}
                className="rounded-full border-2 border-green-600 bg-white hover:bg-green-100 px-3 py-1.5 text-[12px] font-semibold text-green-700"
              >
                Resolve
              </button>
            )}
            {alert.status !== "dismissed" && (
              <button
                onClick={() => changeStatus("dismissed")}
                className="rounded-full border-2 border-gray-700 bg-white hover:bg-gray-200 px-3 py-1.5 text-[12px] font-semibold text-gray-700"
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

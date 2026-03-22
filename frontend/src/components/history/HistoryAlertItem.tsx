import { useState } from "react";
import { ShieldAlert, ChevronDown, ChevronUp, CheckCircle2, AlertTriangle, XCircle } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkBreaks from "remark-breaks";
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
        <span className={`shrink-0 rounded-full px-2 py-0.5 text-[12px] font-bold font-unica ${
          alert.status === "resolved" 
            ? "bg-green-100 text-green-700" 
            : alert.status === "open"
            ? "bg-orange-100 text-orange-700"
            : "bg-gray-200 text-gray-700"
        }`}>
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
          <div className="mb-4 text-sm leading-relaxed text-gray-800 chat-markdown min-w-0">
            <ReactMarkdown
              remarkPlugins={[remarkGfm, remarkBreaks]}
              components={{
                h1: ({ children }) => <h1 className="text-[1.05rem] font-bold mt-3 mb-1">{children}</h1>,
                h2: ({ children }) => <h2 className="text-[1rem] font-bold mt-3 mb-1">{children}</h2>,
                h3: ({ children }) => <h3 className="text-[0.95rem] font-bold mt-2 mb-1">{children}</h3>,
                p: ({ children }) => <p className="mb-2 mt-1 last:mb-0 leading-snug">{children}</p>,
                ul: ({ children }) => <ul className="list-disc pl-5 mb-2 mt-1 space-y-1">{children}</ul>,
                ol: ({ children }) => <ol className="list-decimal pl-5 mb-2 mt-1 space-y-1">{children}</ol>,
                li: ({ children }) => <li className="pl-1">{children}</li>,
                code: ({ children }) => <code className="bg-gray-200 rounded px-1.5 py-0.5 text-[0.85em] font-mono break-words">{children}</code>,
                pre: ({ children }) => <pre className="bg-gray-800 text-gray-100 rounded-lg p-3 my-2 overflow-x-auto text-[0.85em] font-mono whitespace-pre-wrap">{children}</pre>,
                a: ({ children, href }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-[#5271ff] hover:underline break-words">{children}</a>,
                strong: ({ children }) => <strong className="font-bold text-gray-900">{children}</strong>,
              }}
            >
              {alert.analysis}
            </ReactMarkdown>
          </div>

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
            {alert.status === "open" || alert.status === "acknowledged" ? (
              <>
                <button
                  onClick={() => changeStatus("resolved")}
                  className="rounded-full border-2 border-green-600 bg-white hover:bg-green-100 px-3 py-1.5 text-[12px] font-semibold text-green-700 transition-colors"
                >
                  Resolve
                </button>
                <button
                  onClick={() => changeStatus("dismissed")}
                  className="rounded-full border-2 border-gray-500 bg-white hover:bg-gray-100 px-3 py-1.5 text-[12px] font-semibold text-gray-600 transition-colors"
                >
                  Dismiss
                </button>
              </>
            ) : (
              <button
                onClick={() => changeStatus("open")}
                className="rounded-full border-2 border-purple-600 bg-white hover:bg-purple-100 px-3 py-1.5 text-[12px] font-semibold text-purple-700 transition-colors"
              >
                Reopen
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

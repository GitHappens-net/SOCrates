import { useEffect, useRef } from "react";
import { MonitorDot } from "lucide-react";
import type { LogEntry, Severity } from "../data/mockData";

interface SeverityStyle {
  bg: string;
  text: string;
  ring: string;
}

const SEV: Record<Severity, SeverityStyle> = {
  critical: { bg: "bg-red-100",    text: "text-red-700",    ring: "ring-red-400"    },
  high:     { bg: "bg-orange-100", text: "text-orange-700", ring: "ring-orange-400" },
  medium:   { bg: "bg-amber-100",  text: "text-amber-700",  ring: "ring-amber-400"  },
  low:      { bg: "bg-green-100",  text: "text-green-700",  ring: "ring-green-400"  },
};

function SeverityBadge({ level }: { level: Severity }) {
  const c = SEV[level];
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ${c.bg} ${c.text} ${c.ring}`}
    >
      {level}
    </span>
  );
}

interface LiveLogMonitorProps {
  logs: LogEntry[];
}

export default function LiveLogMonitor({ logs }: LiveLogMonitorProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [logs[0]?.id]);

  return (
    <div className="bg-white border border-black flex flex-col rounded-lg">
      {/* Title */}
      <div className="flex items-center gap-2 border-b border-gray-200 px-5 py-3">
        <MonitorDot className="h-4 w-4 text-blue-600" />
        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-500">
          Live Log Stream
        </h3>
        <span className="ml-auto flex items-center gap-1.5 text-xs text-green-600">
          <span className="h-2 w-2 rounded-full bg-green-600" />
          Streaming
        </span>
      </div>

      {/* Table */}
      <div
        ref={containerRef}
        className="max-h-[420px] overflow-y-auto overscroll-contain"
      >
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-white">
            <tr className="border-b border-gray-200 text-left text-gray-500">
              <th className="px-5 py-2.5 font-medium">Timestamp</th>
              <th className="px-3 py-2.5 font-medium">Source IP</th>
              <th className="px-3 py-2.5 font-medium">Event</th>
              <th className="px-3 py-2.5 font-medium">Severity</th>
              <th className="px-3 py-2.5 font-medium">AI Insight</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => {
              const isCritical = log.severity === "critical" || log.severity === "high";
              return (
                <tr
                  key={log.id}
                  className={`border-b border-gray-100 hover:bg-gray-50 ${isCritical ? "row-critical" : ""}`}
                >
                  <td className="whitespace-nowrap px-5 py-2.5 font-mono text-gray-500">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2.5 font-mono text-gray-900">{log.srcIp}</td>
                  <td className="px-3 py-2.5 text-gray-900">{log.eventType}</td>
                  <td className="px-3 py-2.5">
                    <SeverityBadge level={log.severity} />
                  </td>
                  <td className="max-w-[260px] truncate px-3 py-2.5 text-gray-500">
                    {log.aiInsight}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

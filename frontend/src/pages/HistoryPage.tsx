import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { useAlerts } from "@/hooks/useApiData";
import HistoryAlertItem from "@/components/history/HistoryAlertItem";

export default function HistoryPage() {
  const { alerts, loading, reload } = useAlerts();
  const [filter, setFilter] = useState<string>("all");

  const filtered = filter === "all" ? alerts : alerts.filter((a) => a.status === filter);

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
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
                filter === s ? "bg-black text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        <span className="text-xs text-gray-400">{loading ? "Loading..." : `${filtered.length} alerts`}</span>
      </div>

      <div className="space-y-3">
        {filtered.length === 0 && !loading && (
          <p className="py-10 text-center text-sm text-gray-400">No alerts found.</p>
        )}
        {filtered.map((alert) => (
          <HistoryAlertItem key={alert.id} alert={alert} onStatusChange={reload} />
        ))}
      </div>
    </div>
  );
}

import { useState } from "react";
import { ChartColumn } from "lucide-react";
import { useAlerts } from "@/hooks/useApiData";
import HistoryAlertItem from "@/components/history/HistoryAlertItem";

export default function HistoryPage() {
  const { alerts, loading, reload } = useAlerts();
  const [filter, setFilter] = useState<string>("all");

  const filtered = filter === "all" ? alerts : alerts.filter((a) => a.status === filter);

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
      <div className="flex items-center gap-3 rounded-t-xl border-2 border-gray-700 bg-white px-5 py-3">
        <ChartColumn className="h-5 w-5 text-[#5271ff]" />
        <h3 className="text-lg font-unica font-semibold uppercase tracking-wider text-gray-700">
          AI ANALYSIS
        </h3>
        <div className="ml-auto flex items-center gap-2">
          {["all", "open", "acknowledged", "resolved", "dismissed"].map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`rounded-full px-2.5 py-1 text-[12px] font-semibold capitalize transition ${
                filter === s ? "bg-gray-800 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"
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
          <p className="font-unica py-10 text-center text-3xl text-white/80 font-bold">NOTHING FOUND.</p>
        )}
        {filtered.map((alert) => (
          <HistoryAlertItem key={alert.id} alert={alert} onStatusChange={reload} />
        ))}
      </div>
    </div>
  );
}

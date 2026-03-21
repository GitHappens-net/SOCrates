import { useState, useEffect } from "react";
import { ChartColumn } from "lucide-react";
import { useLocation } from "react-router-dom";
import { useAlerts } from "@/hooks/useApiData";
import HistoryAlertItem from "@/components/history/HistoryAlertItem";

export default function HistoryPage() {
  const location = useLocation();
  const { alerts, loading, reload } = useAlerts();
  const [filter, setFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const statusParam = params.get("status");
    if (statusParam && ["all", "open", "resolved", "dismissed"].includes(statusParam)) {
      setFilter(statusParam);
    }
    const severityParam = params.get("severity");
    if (severityParam && ["all", "critical", "high", "medium", "low"].includes(severityParam)) {
      setSeverityFilter(severityParam);
    }
  }, [location.search]);

  const filtered = alerts.filter((a) => {
    const passStatus = filter === "all" || a.status === filter;
    const passSeverity = severityFilter === "all" || a.severity.toLowerCase() === severityFilter;
    return passStatus && passSeverity;
  });

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
      <div className="flex items-center gap-3 rounded-t-xl border-2 border-gray-700 bg-white px-5 py-3">
        <ChartColumn className="h-5 w-5 text-[#5271ff]" />
        <h3 className="text-lg font-unica font-semibold uppercase tracking-wider text-gray-700">
          AI ANALYSIS
        </h3>
        
        <div className="ml-auto flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <label htmlFor="severity-hist" className="text-xs font-semibold text-gray-600 uppercase">Severity:</label>
            <select
              id="severity-hist"
              className="rounded-full border border-gray-300 bg-gray-50 px-2 py-0.5 text-xs font-medium text-gray-700 focus:border-gray-500 focus:outline-none capitalize"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 border-l border-gray-200 pl-4">
            <label className="text-xs font-semibold text-gray-600 uppercase">Status:</label>
            <div className="flex items-center gap-1">
              {["all", "open", "resolved", "dismissed"].map((s) => (
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
          </div>
        </div>
        
        <span className="ml-2 text-xs font-medium text-gray-400 min-w-max border-l border-gray-200 pl-4">
          {loading ? "Loading..." : `${filtered.length} matching`}
        </span>
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

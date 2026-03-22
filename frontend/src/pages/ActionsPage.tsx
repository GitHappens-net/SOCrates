import { useState, useEffect } from "react";
import { Activity } from "lucide-react";
import { useLocation } from "react-router-dom";
import { useActions } from "@/hooks/useApiData";

export default function ActionsPage() {
  const location = useLocation();
  const [filter, setFilter] = useState<string>("all");
  const { actions, loading } = useActions(filter === "all" ? undefined : filter);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const statusParam = params.get("status");
    if (statusParam && ["all", "pending", "success", "failed"].includes(statusParam)) {
      setFilter(statusParam);
    }
  }, [location.search]);

  function getStatusStyle(s: string) {
    switch (s.toLowerCase()) {
      case "pending": return "bg-yellow-100 text-yellow-800 border-yellow-300";
      case "success": return "bg-green-100 text-green-800 border-green-300";
      case "failed": return "bg-red-100 text-red-800 border-red-300";
      default: return "bg-gray-100 text-gray-800 border-gray-300";
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
      <div className="flex items-center gap-3 rounded-t-xl border-2 border-gray-700 bg-white px-5 py-3">
        <Activity className="h-5 w-5 text-[#5271ff]" />
        <h3 className="text-lg font-unica font-semibold uppercase tracking-wider text-gray-700">
          SOAR ACTIONS HISTORY
        </h3>
        
        <div className="ml-auto flex items-center gap-1.5 pl-4">
          <label className="text-xs font-semibold text-gray-600 uppercase">Status:</label>
          <div className="flex items-center gap-1">
            {["all", "pending", "success", "failed"].map((s) => (
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
        
        <span className="ml-2 text-xs font-medium text-gray-400 min-w-max border-l border-gray-200 pl-4">
          {loading ? "Loading..." : `${actions.length} records`}
        </span>
      </div>

      <div className="rounded-xl border-2 border-gray-700 bg-white min-h-[400px]">
        {actions.length === 0 && !loading && (
          <p className="font-unica py-10 text-center text-3xl text-gray-400 font-bold">NO ACTIONS FOUND.</p>
        )}
        
        {actions.length > 0 && (
          <div className="overflow-x-auto rounded-xl">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-gray-50 border-b-2 border-gray-700 text-gray-600 font-bold uppercase text-xs">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Device IP</th>
                  <th className="px-4 py-3">Vendor</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 w-1/3">Context / Parameters</th>
                  <th className="px-4 py-3">Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 text-gray-800 font-medium">
                {actions.map((act) => (
                  <tr key={act.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {new Date(act.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono bg-gray-100 px-2 py-0.5 rounded text-[13px]">{act.device_ip}</span>
                    </td>
                    <td className="px-4 py-3 capitalize">{act.vendor}</td>
                    <td className="px-4 py-3 text-[#5271ff] font-bold">{act.action_type}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-block px-2 py-0.5 rounded-full border text-[11px] font-bold uppercase tracking-wider ${getStatusStyle(act.status)}`}>
                        {act.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-normal align-top">
                      {Object.keys(act.parameters || {}).length > 0 && (
                        <div className="bg-gray-100 rounded p-2 font-mono text-[11px] text-gray-800 break-all border border-gray-200">
                           {Object.entries(act.parameters).map(([k, v]) => (
                             <span key={k} className="mr-3 inline-block">
                               <strong className="text-gray-500">{k}:</strong> {String(v)}
                             </span>
                           ))}
                        </div>
                      )}
                      {act.error && (
                         <div className="mt-1 text-red-600 text-xs font-semibold">Error: {act.error}</div>
                      )}
                    </td>
                     <td className="px-4 py-3 uppercase text-[10px] tracking-wider text-gray-500">
                      {act.source} ({act.requested_by})
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
import { useState } from "react";
import Sidebar, { type ViewId } from "./components/Sidebar";
import Header from "./components/Header";
import MetricCards from "./components/MetricCards";
import TrafficChart from "./components/TrafficChart";
import ThreatDonut from "./components/ThreatDonut";
import LiveLogMonitor from "./components/LiveLogMonitor";
import AIChatPanel from "./components/AIChatPanel";
import useSimulatedData from "./hooks/useSimulatedData";
import { Network } from "lucide-react";

export default function App() {
  const [activeView, setActiveView] = useState<ViewId>("dashboard");
  const { logs, trafficData, sparklines, metrics } = useSimulatedData();

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <Sidebar activeView={activeView} onNavigate={setActiveView} />

      {/* Main content area */}
      <div className="bg-gray-50 ml-[72px] flex flex-1 flex-col">
        {/* Header */}
        <div className="px-5 pt-4">
          <Header />
        </div>

        {/* Body */}
        <div className="flex flex-1 gap-4 overflow-hidden px-5 py-4">
          {/* Left column — dashboard / logs */}
          <div className="flex flex-1 flex-col gap-4 overflow-y-auto pr-1">
            {(activeView === "dashboard" || activeView === "ai") && (
              <>
                <MetricCards metrics={metrics} sparklines={sparklines} />
                <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
                  <div className="xl:col-span-2">
                    <TrafficChart data={trafficData} />
                  </div>
                  <ThreatDonut />
                </div>
              </>
            )}

            {(activeView === "dashboard" || activeView === "logs") && (
              <LiveLogMonitor logs={logs} />
            )}

            {activeView === "topology" && (
              <div className="bg-white border border-black flex flex-1 flex-col items-center justify-center rounded-lg p-10">
                <Network className="mb-4 h-16 w-16 text-gray-300" />
                <h2 className="text-lg font-semibold text-gray-500">
                  Network Topology
                </h2>
                <p className="mt-2 max-w-md text-center text-sm text-gray-500">
                  Interactive topology map will render here. Connect to a live
                  data source to visualise network segments, subnets, and
                  real-time traffic flows between nodes.
                </p>
              </div>
            )}
          </div>

          {/* Right column — AI Chat Panel (always visible) */}
          <div className="hidden w-[380px] shrink-0 lg:block xl:w-[420px]">
            <AIChatPanel />
          </div>
        </div>
      </div>
    </div>
  );
}

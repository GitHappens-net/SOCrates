import { useState } from "react";
import Sidebar, { type ViewId } from "./components/Sidebar";
import Header from "./components/Header";
import DashboardView from "./components/DashboardView";
import DevicesView from "./components/DevicesView";
import LogsView from "./components/LogsView";
import HistoryView from "./components/HistoryView";
import AIChatPanel from "./components/AIChatPanel";
import { DataProvider } from "./context/DataContext";

function AppContent() {
  const [activeView, setActiveView] = useState<ViewId>("dashboard");
  const [chatWidth, setChatWidth] = useState(420);

  function handleDragStart(e: React.PointerEvent<HTMLDivElement>): void {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = chatWidth;

    const onMove = (ev: PointerEvent) => {
      const delta = startX - ev.clientX;
      const next = Math.max(320, Math.min(700, startWidth + delta));
      setChatWidth(next);
    };

    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };

    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar activeView={activeView} onNavigate={setActiveView} />

      <div className="ml-[72px] flex flex-1 flex-col overflow-hidden">
        <div className="px-5 pt-4">
          <Header />
        </div>

        <div className="flex min-h-0 flex-1 gap-4 px-5 py-4">
          {/* Main panel */}
          <div className="min-h-0 flex-1 overflow-y-auto pr-1">
            {activeView === "dashboard" && <DashboardView />}
            {activeView === "devices" && <DevicesView />}
            {activeView === "logs" && <LogsView />}
            {activeView === "history" && <HistoryView />}
          </div>

          {/* AI Chat sidebar */}
          <div
            onPointerDown={handleDragStart}
            className="hidden w-3 shrink-0 cursor-col-resize rounded bg-gray-100 transition hover:bg-gray-300 lg:block"
            title="Drag to resize chat"
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize chat panel"
          />
          <div
            className="hidden shrink-0 lg:flex"
            style={{ width: `${chatWidth}px` }}
          >
            <AIChatPanel />
          </div>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <DataProvider>
      <AppContent />
    </DataProvider>
  );
}

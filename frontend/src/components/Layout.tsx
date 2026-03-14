import { useMemo, useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import Sidebar, { type ViewId } from "@/components/Sidebar";
import Header from "@/components/Header";
import AIChatPanel from "@/components/AIChatPanel";

const PATH_TO_VIEW: Record<string, ViewId> = {
  "/dashboard": "dashboard",
  "/devices": "devices",
  "/logs": "logs",
  "/history": "history",
};

const VIEW_TO_PATH: Record<ViewId, string> = {
  dashboard: "/dashboard",
  devices: "/devices",
  logs: "/logs",
  history: "/history",
};

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [chatWidth, setChatWidth] = useState(420);

  const activeView = useMemo<ViewId>(() => {
    const path = location.pathname.toLowerCase();
    return PATH_TO_VIEW[path] ?? "dashboard";
  }, [location.pathname]);

  function handleNavigate(view: ViewId): void {
    navigate(VIEW_TO_PATH[view]);
  }

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
    <div className="h-screen flex overflow-hidden bg-blue-900">
      <Sidebar activeView={activeView} onNavigate={handleNavigate} />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />

        <div className="flex min-h-0 flex-1 gap-4 px-6 py-5">
          {/* Main view injection point */}
          <div className="min-h-0 flex-1 overflow-y-auto">
            <Outlet />
          </div>

          {/* AI Chat sidebar */}
           <div
            onPointerDown={handleDragStart}
            className="hidden w-3 shrink-0 cursor-col-resize rounded bg-blue-700/40 transition hover:bg-blue-500/50 lg:block"
            title="Drag to resize chat"
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize chat panel"
          />
          <div className="hidden shrink-0 lg:flex" style={{ width: `${chatWidth}px` }}>
            <AIChatPanel />
          </div>
        </div>
      </div>
    </div>
  );
}

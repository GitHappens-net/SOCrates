import { LayoutDashboard, MonitorDot, Network, History } from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type ViewId = "dashboard" | "devices" | "logs" | "history";

interface NavItem {
  id: ViewId;
  icon: LucideIcon;
  label: string;
}

interface SidebarProps {
  activeView: ViewId;
  onNavigate: (view: ViewId) => void;
}

const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", icon: LayoutDashboard, label: "Dashboard"      },
  { id: "devices",   icon: Network,         label: "Devices"        },
  { id: "logs",      icon: MonitorDot,      label: "Logs"           },
  { id: "history",   icon: History,         label: "Analysis History"},
];

export default function Sidebar({ activeView, onNavigate }: SidebarProps) {
  return (
    <aside className="z-40 flex w-24 bg-gray-100 shrink-0 flex-col items-center gap-2 py-5">
      {/* Nav icons */}
      {NAV_ITEMS.map(({ id, icon: Icon, label }) => {
        const active = activeView === id;
        return (
          <button
            key={id}
            onClick={() => onNavigate(id)}
            title={label}
            className={`group relative flex h-11 w-11 items-center justify-center rounded-lg border transition-colors ${
              active
                ? "border-cyan-300/80 bg-cyan-400/20 text-white"
                : "border-transparent text-blue-100/80 hover:border-blue-300/60 hover:bg-blue-700/40 hover:text-white"
            }`}
          >
            <Icon className="h-5 w-5" />
            {/* Tooltip */}
            <span className="pointer-events-none absolute left-full ml-3 whitespace-nowrap rounded border border-blue-900 bg-white px-2.5 py-1 text-xs text-blue-950 opacity-0 shadow-sm transition-opacity group-hover:opacity-100">
              {label}
            </span>
          </button>
        );
      })}
    </aside>
  );
}

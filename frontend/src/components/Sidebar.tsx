import { LayoutDashboard, MonitorDot, Network, History, ShieldCheck } from "lucide-react";
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
    <aside className="fixed inset-y-0 left-0 z-40 flex w-[72px] flex-col items-center gap-2 border-r border-gray-200 bg-white py-5">
      {/* Logo */}
      <div className="mb-6 flex h-10 w-10 items-center justify-center rounded-lg border border-black">
        <ShieldCheck className="h-6 w-6 text-black" />
      </div>

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
                ? "border-black bg-black text-white"
                : "border-transparent text-gray-400 hover:border-gray-300 hover:bg-gray-50 hover:text-black"
            }`}
          >
            <Icon className="h-5 w-5" />
            {/* Tooltip */}
            <span className="pointer-events-none absolute left-full ml-3 whitespace-nowrap rounded border border-black bg-white px-2.5 py-1 text-xs text-black opacity-0 shadow-sm transition-opacity group-hover:opacity-100">
              {label}
            </span>
          </button>
        );
      })}
    </aside>
  );
}

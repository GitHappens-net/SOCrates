import { LayoutDashboard, MonitorDot, Network, ChartColumn } from "lucide-react";
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
  { id: "history",   icon: ChartColumn,         label: "AI Analysis"},
  { id: "devices",   icon: Network,         label: "Devices"        },
  { id: "logs",      icon: MonitorDot,      label: "Logs"           },
];

export default function Sidebar({ activeView, onNavigate }: SidebarProps) {
  return (
    <aside className="w-20 bg-gray-100 shrink-0 flex flex-col items-center gap-4 py-5 self-stretch">
      {/* Nav icons */}
      {NAV_ITEMS.map(({ id, icon: Icon, label }) => {
        const active = activeView === id;
        return (
          <button
            key={id}
            onClick={() => onNavigate(id)}
            className={`group relative flex h-10 w-10 items-center justify-center rounded-xl border ${
              active
                ? "bg-[#5271ff] border border-[#5271ff] text-white"
                : "border-transparent text-gray-700 hover:border-2 hover:border-gray-700 hover:bg-gray-200"
            }`}
            title={label}
          >
            <Icon className="h-5 w-5" />
          </button>
        );
      })}
    </aside>
  );
}

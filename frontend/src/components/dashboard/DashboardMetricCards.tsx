import type { LucideIcon } from "lucide-react";

export interface DashboardMetricCardProps {
  icon: LucideIcon;
  label: string;
  value: string;
  accent: Accent;
}

export type Accent = "blue" | "red" | "orange" | "green";

const COLOR: Record<Accent, { bg: string }> = {
  blue: { bg: "bg-blue-600/80" },
  red: { bg: "bg-red-600/80" },
  orange: { bg: "bg-amber-600/80" },
  green: { bg: "bg-green-600/80" },
};

export default function DashboardMetricCard({ icon: Icon, label, value, accent }: DashboardMetricCardProps) {
  const c = COLOR[accent];
  return (
    <div className="flex flex-col justify-between rounded-xl border-2 border-gray-700 bg-gray-100 p-5">
      <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${c.bg}`}>
        <Icon className="h-5 w-5 text-white" />
      </div>
      <div className="mt-4">
        <p className="text-md font-unica uppercase tracking-wider font-semibold text-gray-700">{label}</p>
        <p className="mt-1 text-3xl font-unica font-bold text-black">{value}</p>
      </div>
    </div>
  );
}

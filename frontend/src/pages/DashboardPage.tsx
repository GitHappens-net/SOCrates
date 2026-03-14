import { useAlerts, useStats } from "@/hooks/useApiData";
import { Activity, MonitorDot, ShieldAlert } from "lucide-react";
import DashboardMetricCard from "@/components/dashboard/DashboardMetricCards";
import TopDevicesChart from "@/components/dashboard/TopDevicesChart";
import VendorDonutCard from "@/components/dashboard/VendorDonutCard";

const VENDOR_PALETTE = [
  "#2563eb",
  "#dc2626",
  "#16a34a",
  "#d97706",
  "#7c3aed",
  "#06b6d4",
  "#64748b",
];

export default function DashboardPage() {
  const { stats } = useStats();
  const { alerts } = useAlerts();

  const openAlerts = alerts.filter((a) => a.status === "open").length;
  const highAlerts = alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;

  const vendorData = stats
    ? Object.entries(stats.by_vendor).map(([name, value], i) => ({
        name,
        value,
        fill: VENDOR_PALETTE[i % VENDOR_PALETTE.length],
      }))
    : [];

  const deviceData = stats
    ? Object.entries(stats.by_device)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <DashboardMetricCard
          icon={Activity}
          label="Total Logs"
          value={stats?.total_logs !== undefined ? stats.total_logs.toLocaleString() : "-"}
          accent="blue"
        />
        <DashboardMetricCard
          icon={ShieldAlert}
          label="Open Alerts"
          value={String(openAlerts)}
          accent="red"
        />
        <DashboardMetricCard
          icon={ShieldAlert}
          label="High / Critical"
          value={String(highAlerts)}
          accent="orange"
        />
        <DashboardMetricCard
          icon={MonitorDot}
          label="Unique Devices"
          value={stats ? String(Object.keys(stats.by_device).length) : "-"}
          accent="green"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <TopDevicesChart data={deviceData} />
        <VendorDonutCard data={vendorData} totalLogs={stats?.total_logs ?? 0} />
      </div>
    </div>
  );
}

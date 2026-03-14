import { useAlerts, useStats, useDevices } from "@/hooks/useApiData";
import { Activity, MonitorDot, ShieldAlert } from "lucide-react";
import DashboardMetricCard from "@/components/dashboard/DashboardMetricCards";
import TopDevicesChart from "@/components/dashboard/TopDevicesChart";
import VendorDonutCard from "@/components/dashboard/VendorDonutCard";
import { getVendorColor } from "@/utils/colors";

export default function DashboardPage() {
  const { stats } = useStats();
  const { alerts } = useAlerts();
  const { devices } = useDevices();

  const openAlerts = alerts.filter((a) => a.status === "open").length;
  const highAlerts = alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;

  const vendorData = stats
    ? Object.entries(stats.by_vendor)
        .sort(([a], [b]) => a.localeCompare(b)) // keep ordering stable
        .map(([name, value]) => ({
          name,
          value,
          fill: getVendorColor(name),
        }))
    : [];

  const deviceData = stats
    ? Object.entries(stats.by_device)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([name, value]) => {
          // Attempt to find the vendor for this device by matching IP or Hostname
          const matchedDevice = devices.find(d => d.ip === name || d.hostname === name);
          const vendor = matchedDevice?.vendor || "Unknown";
          return { 
            name, 
            value,
            fill: getVendorColor(vendor)
          };
        })
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

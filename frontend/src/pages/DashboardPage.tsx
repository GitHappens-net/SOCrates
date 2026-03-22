import { useAlerts, useStats, useDevices } from "@/hooks/useApiData";
import { Activity, MonitorDot, ShieldAlert, CheckCircle, Server, AlertTriangle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import DashboardMetricCard from "@/components/dashboard/DashboardMetricCards";
import TopDevicesChart from "@/components/dashboard/TopDevicesChart";
import VendorDonutCard from "@/components/dashboard/VendorDonutCard";
import AlertsBySeverityCard from "@/components/dashboard/AlertsBySeverityCard";
import { getVendorColor } from "@/utils/colors";

export default function DashboardPage() {
  const { stats } = useStats();
  const { alerts } = useAlerts();
  const { devices } = useDevices();
  const navigate = useNavigate();

  const openAlerts = alerts.filter((a) => a.status === "open").length;
  const resolvedAlerts = alerts.filter((a) => a.status === "resolved").length;
  const highAlerts = alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;
  const trackedVendors = stats ? Object.keys(stats.by_vendor).length : 0;

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

  const SEVERITY_COLORS: Record<string, string> = {
    info: "#4f80ed",     // blue
    low: "#43b36c",      // green
    medium: "#eab308",   // yellow
    high: "#df9036",     // orange
    critical: "#e14f4f", // red
  };

  const severityCounts = alerts
    .filter(a => a.status === "open")
    .reduce((acc, alert) => {
      const s = alert.severity.toLowerCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

  const severityData = Object.entries(severityCounts)
    .map(([name, value]) => ({
      name,
      value,
      fill: SEVERITY_COLORS[name] || "#6b7280"
    }))
    .sort((a, b) => b.value - a.value);

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <DashboardMetricCard
          icon={Activity}
          label="Total Logs"
          value={stats?.total_logs !== undefined ? stats.total_logs.toLocaleString() : "-"}
          accent="blue"
          onClick={() => navigate("/logs")}
        />
        <DashboardMetricCard
          icon={ShieldAlert}
          label="Open Alerts"
          value={String(openAlerts)}
          accent="red"
          onClick={() => navigate("/history?status=open")}
        />
        <DashboardMetricCard
          icon={MonitorDot}
          label="Unique Devices"
          value={stats ? String(Object.keys(stats.by_device).length) : "-"}
          accent="green"
          onClick={() => navigate("/devices")}
        />
        <DashboardMetricCard
          icon={AlertTriangle}
          label="High / Critical"
          value={String(highAlerts)}
          accent="orange"
          onClick={() => navigate("/logs?severity=high-critical")}
        />
        <DashboardMetricCard
          icon={CheckCircle}
          label="Resolved Alerts"
          value={String(resolvedAlerts)}
          accent="green"
          onClick={() => navigate("/history?status=resolved")}
        />
        <DashboardMetricCard
          icon={Server}
          label="Tracked Vendors"
          value={String(trackedVendors)}
          accent="blue"
          onClick={() => navigate("/logs?focus=vendor")}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        <TopDevicesChart data={deviceData} />
        <VendorDonutCard data={vendorData} totalLogs={stats?.total_logs ?? 0} />
        <AlertsBySeverityCard data={severityData} totalAlerts={openAlerts} />
      </div>
    </div>
  );
}

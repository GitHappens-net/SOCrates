import {
  Activity,
  ShieldAlert,
  MonitorDot,
  Server,
} from "lucide-react";
import { useStats, useAlerts } from "../hooks/useApiData";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";
import type { TooltipProps } from "recharts";

/* ── Pie colors ──────────────────────────────────────────────────── */

const VENDOR_PALETTE = [
  "#2563eb", "#dc2626", "#16a34a", "#d97706", "#7c3aed", "#06b6d4", "#64748b",
];

/* ── Custom tooltip ──────────────────────────────────────────────── */

function PieTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const d = payload[0];
  return (
    <div className="rounded border border-black bg-white px-3 py-2 text-xs shadow-sm">
      <p className="font-semibold text-gray-900">{d.name}</p>
      <p className="text-gray-600">{d.value} logs</p>
    </div>
  );
}

/* ── Main Dashboard View ─────────────────────────────────────────── */

export default function DashboardView() {
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
      {/* Metric cards row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          icon={Activity}
          label="Total Logs"
          value={stats?.total_logs.toLocaleString() ?? "—"}
          accent="blue"
        />
        <MetricCard
          icon={ShieldAlert}
          label="Open Alerts"
          value={String(openAlerts)}
          accent="red"
        />
        <MetricCard
          icon={ShieldAlert}
          label="High / Critical"
          value={String(highAlerts)}
          accent="orange"
        />
        <MetricCard
          icon={MonitorDot}
          label="Unique Devices"
          value={stats ? String(Object.keys(stats.by_device).length) : "—"}
          accent="green"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Logs per device bar chart */}
        <div className="rounded-lg border border-black bg-white p-5 xl:col-span-2">
          <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-500">
            Top Devices by Log Volume
          </h3>
          <div className="h-[280px] w-full">
            {deviceData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={deviceData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: "#6b7280", fontSize: 10 }}
                    axisLine={{ stroke: "#e5e7eb" }}
                    tickLine={false}
                    angle={-25}
                    textAnchor="end"
                    height={50}
                  />
                  <YAxis tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#2563eb" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-gray-400">
                <Server className="mr-2 h-5 w-5" /> No data yet
              </div>
            )}
          </div>
        </div>

        {/* Vendor distribution donut */}
        <div className="flex flex-col rounded-lg border border-black bg-white p-5">
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-gray-500">
            Logs by Vendor
          </h3>
          <div className="flex flex-1 items-center justify-center">
            {vendorData.length > 0 ? (
              <div className="relative h-[220px] w-[220px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={vendorData}
                      dataKey="value"
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={95}
                      paddingAngle={3}
                      cornerRadius={4}
                      animationDuration={800}
                    >
                      {vendorData.map((entry, idx) => (
                        <Cell key={idx} fill={entry.fill} stroke="transparent" />
                      ))}
                    </Pie>
                    <Tooltip content={<PieTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-bold text-gray-900">{stats?.total_logs ?? 0}</span>
                  <span className="text-[10px] uppercase tracking-wider text-gray-500">Logs</span>
                </div>
              </div>
            ) : (
              <p className="text-sm text-gray-400">No data yet</p>
            )}
          </div>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs">
            {vendorData.map((t) => (
              <span key={t.name} className="flex items-center gap-1.5 text-gray-500">
                <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: t.fill }} />
                {t.name}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Metric Card ─────────────────────────────────────────────────── */

type Accent = "blue" | "red" | "orange" | "green";

const COLOR: Record<Accent, { bg: string; text: string }> = {
  blue:   { bg: "bg-blue-50 border-blue-600",   text: "text-blue-700"  },
  red:    { bg: "bg-red-50 border-red-600",     text: "text-red-700"   },
  orange: { bg: "bg-amber-50 border-amber-500", text: "text-amber-700" },
  green:  { bg: "bg-green-50 border-green-600", text: "text-green-700" },
};

function MetricCard({
  icon: Icon,
  label,
  value,
  accent,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  accent: Accent;
}) {
  const c = COLOR[accent];
  return (
    <div className="flex flex-col justify-between rounded-lg border border-black bg-white p-5">
      <div className={`flex h-10 w-10 items-center justify-center rounded-lg border ${c.bg}`}>
        <Icon className={`h-5 w-5 ${c.text}`} />
      </div>
      <div className="mt-4">
        <p className="text-xs uppercase tracking-wider text-gray-500">{label}</p>
        <p className="mt-1 text-2xl font-bold text-black">{value}</p>
      </div>
    </div>
  );
}

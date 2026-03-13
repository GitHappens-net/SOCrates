import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TooltipProps } from "recharts";
import type { TrafficPoint } from "../data/mockData";

interface TrafficChartProps {
  data: TrafficPoint[];
}

function CustomTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white border border-black rounded px-3 py-2 text-xs shadow-sm">
      <p className="mb-1 font-semibold text-gray-900">{label}</p>
      {payload.map((p) => (
        <p key={p.dataKey as string} style={{ color: p.stroke }}>
          {p.dataKey === "inbound" ? "▲ In" : "▼ Out"}: {p.value} Mbps
        </p>
      ))}
    </div>
  );
}

export default function TrafficChart({ data }: TrafficChartProps) {
  return (
    <div className="bg-white border border-black rounded-lg p-5">
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-500">
        Network Traffic — Inbound / Outbound
      </h3>
      <div className="h-[280px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
            <defs>
              <linearGradient id="gIn" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#2563eb" stopOpacity={0.25} />
                <stop offset="100%" stopColor="#2563eb" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gOut" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#7c3aed" stopOpacity={0.2} />
                <stop offset="100%" stopColor="#7c3aed" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis
              dataKey="time"
              tick={{ fill: "#6b7280", fontSize: 11 }}
              axisLine={{ stroke: "#e5e7eb" }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "#6b7280", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={45}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="inbound"
              stroke="#2563eb"
              strokeWidth={2}
              fill="url(#gIn)"
              dot={false}
              animationDuration={500}
            />
            <Area
              type="monotone"
              dataKey="outbound"
              stroke="#7c3aed"
              strokeWidth={2}
              fill="url(#gOut)"
              dot={false}
              animationDuration={500}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-3 flex gap-5 text-xs text-gray-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-blue-600" />
          Inbound
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full bg-violet-700" />
          Outbound
        </span>
      </div>
    </div>
  );
}


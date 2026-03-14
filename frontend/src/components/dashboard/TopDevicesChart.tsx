import { Server } from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";

interface DevicePoint {
  name: string;
  value: number;
}

interface TopDevicesChartProps {
  data: DevicePoint[];
}

export default function TopDevicesChart({ data }: TopDevicesChartProps) {
  return (
    <div className="rounded-lg border border-black bg-white p-5 xl:col-span-2">
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-500">
        Top Devices by Log Volume
      </h3>
      <div className="h-[280px] w-full">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
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
  );
}

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { TooltipProps } from "recharts";

interface VendorSlice {
  name: string;
  value: number;
  fill: string;
}

interface VendorDonutCardProps {
  data: VendorSlice[];
  totalLogs: number;
}

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

export default function VendorDonutCard({ data, totalLogs }: VendorDonutCardProps) {
  return (
    <div className="flex flex-col rounded-lg border border-black bg-white p-5">
      <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-gray-500">
        Logs by Vendor
      </h3>
      <div className="flex flex-1 items-center justify-center">
        {data.length > 0 ? (
          <div className="relative h-[220px] w-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  cx="50%"
                  cy="50%"
                  innerRadius={65}
                  outerRadius={95}
                  paddingAngle={3}
                  cornerRadius={4}
                  animationDuration={800}
                >
                  {data.map((entry, idx) => (
                    <Cell key={idx} fill={entry.fill} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip content={<PieTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-bold text-gray-900">{totalLogs}</span>
              <span className="text-[10px] uppercase tracking-wider text-gray-500">Logs</span>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-400">No data yet</p>
        )}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs">
        {data.map((t) => (
          <span key={t.name} className="flex items-center gap-1.5 text-gray-500">
            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: t.fill }} />
            {t.name}
          </span>
        ))}
      </div>
    </div>
  );
}

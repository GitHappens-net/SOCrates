import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { TooltipProps } from "recharts";
import { THREAT_DISTRIBUTION, type ThreatDistributionItem } from "../data/mockData";

function CustomTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const d = payload[0];
  const item = d.payload as ThreatDistributionItem;
  return (
    <div className="bg-white border border-black rounded px-3 py-2 text-xs shadow-sm">
      <p className="font-semibold" style={{ color: item.fill }}>
        {d.name}
      </p>
      <p className="text-gray-900">{d.value}% of attacks</p>
    </div>
  );
}

export default function ThreatDonut() {
  return (
    <div className="bg-white border border-black flex flex-col rounded-lg p-5">
      <h3 className="mb-2 text-sm font-semibold uppercase tracking-wider text-gray-500">
        Threat Distribution
      </h3>
      <div className="flex flex-1 items-center justify-center">
        <div className="relative h-[220px] w-[220px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={THREAT_DISTRIBUTION}
                dataKey="value"
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={95}
                paddingAngle={3}
                cornerRadius={4}
                animationDuration={800}
              >
                {THREAT_DISTRIBUTION.map((entry, idx) => (
                  <Cell key={idx} fill={entry.fill} stroke="transparent" />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold text-gray-900">100</span>
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Threats</span>
          </div>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs">
        {THREAT_DISTRIBUTION.map((t) => (
          <span key={t.name} className="flex items-center gap-1.5 text-gray-500">
            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: t.fill }} />
            {t.name}
          </span>
        ))}
      </div>
    </div>
  );
}


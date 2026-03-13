import { Activity, ShieldOff, AlertOctagon, BrainCircuit, TrendingUp, TrendingDown } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Area, AreaChart, ResponsiveContainer } from "recharts";
import type { Metrics, Sparklines, SparkPoint } from "../data/mockData";

type AccentColor = "blue" | "red" | "orange" | "green";

interface MetricCardProps {
  icon: LucideIcon;
  label: string;
  value: string;
  delta: number;
  accent: AccentColor;
  sparkData: SparkPoint[];
}

const COLOR_MAP: Record<AccentColor, { bg: string; text: string; stroke: string; fill: string }> = {
  blue:   { bg: "bg-blue-50 border border-blue-600",   text: "text-blue-700",   stroke: "#2563eb", fill: "rgba(37,99,235,0.1)"  },
  red:    { bg: "bg-red-50 border border-red-600",     text: "text-red-700",    stroke: "#dc2626", fill: "rgba(220,38,38,0.1)"   },
  orange: { bg: "bg-amber-50 border border-amber-500", text: "text-amber-700",  stroke: "#d97706", fill: "rgba(217,119,6,0.1)"   },
  green:  { bg: "bg-green-50 border border-green-600", text: "text-green-700",  stroke: "#16a34a", fill: "rgba(22,163,74,0.1)"   },
};

function MetricCard({ icon: Icon, label, value, delta, accent, sparkData }: MetricCardProps) {
  const up = delta >= 0;
  const TrendIcon = up ? TrendingUp : TrendingDown;
  const c = COLOR_MAP[accent];

  return (
    <div className="bg-white border border-black flex flex-col justify-between rounded-lg p-5">
      <div className="flex items-start justify-between">
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${c.bg}`}>
          <Icon className={`h-5 w-5 ${c.text}`} />
        </div>
        <div className="sparkline-container">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={sparkData}>
              <defs>
                <linearGradient id={`sp-${accent}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={c.stroke} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={c.stroke} stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="v"
                stroke={c.stroke}
                strokeWidth={1.5}
                fill={`url(#sp-${accent})`}
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="mt-4">
        <p className="text-xs uppercase tracking-wider text-gray-500">{label}</p>
        <p className="mt-1 text-2xl font-bold text-black">{value}</p>
      </div>

      <div className="mt-2 flex items-center gap-1 text-xs">
        <TrendIcon className={`h-3.5 w-3.5 ${up ? "text-green-600" : "text-red-600"}`} />
        <span className={up ? "text-green-600" : "text-red-600"}>
          {up ? "+" : ""}{delta}%
        </span>
        <span className="ml-1 text-gray-500">vs last hour</span>
      </div>
    </div>
  );
}

interface MetricCardsProps {
  metrics: Metrics;
  sparklines: Sparklines;
}

export default function MetricCards({ metrics, sparklines }: MetricCardsProps) {
  const cards: MetricCardProps[] = [
    {
      icon: Activity,
      label: "Total Traffic",
      value: metrics.totalTraffic.toLocaleString(),
      delta: 12.4,
      accent: "blue",
      sparkData: sparklines.traffic,
    },
    {
      icon: ShieldOff,
      label: "Blocked Threats",
      value: metrics.blockedThreats.toLocaleString(),
      delta: 3.1,
      accent: "red",
      sparkData: sparklines.blocked,
    },
    {
      icon: AlertOctagon,
      label: "Active Anomalies",
      value: String(metrics.activeAnomalies),
      delta: -8.2,
      accent: "orange",
      sparkData: sparklines.anomalies,
    },
    {
      icon: BrainCircuit,
      label: "AI Confidence",
      value: `${metrics.aiConfidence.toFixed(1)}%`,
      delta: 0.4,
      accent: "green",
      sparkData: sparklines.confidence,
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((c) => (
        <MetricCard key={c.label} {...c} />
      ))}
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import {
  generateLogEntry,
  randomBetween,
  seedSparkline,
  seedTrafficData,
  type LogEntry,
  type TrafficPoint,
  type Metrics,
  type Sparklines,
  type SparkPoint,
} from "../data/mockData";

export interface SimulatedData {
  logs: LogEntry[];
  trafficData: TrafficPoint[];
  sparklines: Sparklines;
  metrics: Metrics;
}

export default function useSimulatedData(): SimulatedData {
  const logId = useRef(1);

  const [logs, setLogs] = useState<LogEntry[]>(() =>
    Array.from({ length: 25 }, () => generateLogEntry(logId.current++))
  );

  const [trafficData, setTrafficData] = useState<TrafficPoint[]>(seedTrafficData);

  const [sparklines, setSparklines] = useState<Sparklines>({
    traffic: seedSparkline(),
    blocked: seedSparkline(),
    anomalies: seedSparkline(),
    confidence: seedSparkline(),
  });

  const [metrics, setMetrics] = useState<Metrics>({
    totalTraffic: 128_473,
    blockedThreats: 347,
    activeAnomalies: 12,
    aiConfidence: 97.3,
  });

  // Tick: add a new log every 1.5s
  useEffect(() => {
    const iv = setInterval(() => {
      setLogs((prev) => {
        const entry = generateLogEntry(logId.current++);
        return [entry, ...prev].slice(0, 200);
      });
    }, 1500);
    return () => clearInterval(iv);
  }, []);

  // Tick: update traffic chart every 3s
  useEffect(() => {
    const iv = setInterval(() => {
      setTrafficData((prev) => {
        const t = new Date();
        const point: TrafficPoint = {
          time: t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          inbound: randomBetween(200, 650),
          outbound: randomBetween(100, 420),
        };
        return [...prev.slice(1), point];
      });
    }, 3000);
    return () => clearInterval(iv);
  }, []);

  // Tick: update metrics & sparklines every 4d
  useEffect(() => {
    const iv = setInterval(() => {
      setMetrics((m) => ({
        totalTraffic: m.totalTraffic + randomBetween(80, 400),
        blockedThreats: m.blockedThreats + (Math.random() > 0.6 ? 1 : 0),
        activeAnomalies: Math.max(0, m.activeAnomalies + (Math.random() > 0.5 ? 1 : -1)),
        aiConfidence: Math.min(100, Math.max(90, m.aiConfidence + (Math.random() - 0.5) * 0.8)),
      }));
      setSparklines((s) => {
        const bump = (arr: SparkPoint[]): SparkPoint[] => [
          ...arr.slice(1),
          { v: randomBetween(30, 100) },
        ];
        return {
          traffic: bump(s.traffic),
          blocked: bump(s.blocked),
          anomalies: bump(s.anomalies),
          confidence: bump(s.confidence),
        };
      });
    }, 4000);
    return () => clearInterval(iv);
  }, []);

  return { logs, trafficData, sparklines, metrics };
}

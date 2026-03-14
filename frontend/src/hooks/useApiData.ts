import { useCallback, useEffect, useRef, useState } from "react";
import { useDataMode } from "@/context/DataContext";
import { fetchDevices, fetchLogs, fetchAlerts, fetchStats, fetchDeviceLogs } from "@/api/client";
import type { ApiAlert, ApiDevice, ApiLog, ApiStats } from "@/api/types";
import { MOCK_DEVICES, MOCK_ALERTS, MOCK_STATS, generateMockLogs } from "@/api/data/mockApi";

/* Devices */
export function useDevices(pollMs = 10000) {
  const { useMock } = useDataMode();
  const [devices, setDevices] = useState<ApiDevice[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (useMock) {
      setDevices(MOCK_DEVICES);
      setLoading(false);
      return;
    }
    let cancelled = false;
    const load = () => {
      fetchDevices()
        .then((d) => { if (!cancelled) { setDevices(d); setLoading(false); } })
        .catch(() => { if (!cancelled) setLoading(false); });
    };
    load();
    const iv = setInterval(load, pollMs);
    return () => { cancelled = true; clearInterval(iv); };
  }, [useMock, pollMs]);

  return { devices, loading };
}

/* Logs (with polling) */
export function useLogs(limit = 100, pollMs = 5000) {
  const { useMock } = useDataMode();
  const [logs, setLogs] = useState<ApiLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (useMock) {
      setLogs(generateMockLogs(limit));
      setLoading(false);
      const iv = setInterval(() => setLogs(generateMockLogs(limit)), pollMs);
      return () => clearInterval(iv);
    }
    let cancelled = false;
    const load = () => {
      fetchLogs({ limit })
        .then((d) => { if (!cancelled) { setLogs(d); setLoading(false); } })
        .catch(() => { if (!cancelled) setLoading(false); });
    };
    load();
    const iv = setInterval(load, pollMs);
    return () => { cancelled = true; clearInterval(iv); };
  }, [useMock, limit, pollMs]);

  return { logs, loading };
}

/* Device Logs */
export function useDeviceLogs(ip: string | null, limit = 50) {
  const { useMock } = useDataMode();
  const [logs, setLogs] = useState<ApiLog[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!ip) { setLogs([]); return; }
    if (useMock) {
      setLogs(generateMockLogs(limit).map((l) => ({ ...l, source_ip: ip })));
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    fetchDeviceLogs(ip, { limit })
      .then((d) => { if (!cancelled) setLogs(d); })
      .catch(() => { if (!cancelled) setLogs([]); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [ip, useMock, limit]);

  return { logs, loading };
}

/* Health Check */
export function useHealthCheck(pollMs = 10000) {
  const { useMock } = useDataMode();
  const [isOnline, setIsOnline] = useState(true);

  useEffect(() => {
    if (useMock) {
      setIsOnline(true);
      return;
    }
    let cancelled = false;
    const check = async () => {
      try {
        await fetchStats();
        if (!cancelled) setIsOnline(true);
      } catch {
        if (!cancelled) setIsOnline(false);
      }
    };
    check();
    const iv = setInterval(check, pollMs);
    return () => { cancelled = true; clearInterval(iv); };
  }, [useMock, pollMs]);

  return isOnline;
}
export function useAlerts(pollMs = 10000) {
  const { useMock } = useDataMode();
  const [alerts, setAlerts] = useState<ApiAlert[]>([]);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(() => {
    if (useMock) {
      setAlerts(MOCK_ALERTS);
      setLoading(false);
      return;
    }
    fetchAlerts({ limit: 200 })
      .then((d) => { setAlerts(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [useMock]);

  useEffect(() => {
    reload();
    const iv = setInterval(reload, pollMs);
    return () => clearInterval(iv);
  }, [reload, pollMs]);

  return { alerts, loading, reload };
}

/* Stats */
export function useStats(pollMs = 8000) {
  const { useMock } = useDataMode();
  const [stats, setStats] = useState<ApiStats | null>(null);
  const prevTotal = useRef(0);

  useEffect(() => {
    if (useMock) {
      setStats(MOCK_STATS);
      prevTotal.current = MOCK_STATS.total_logs;
      return;
    }
    let cancelled = false;
    const load = () => {
      fetchStats()
        .then((d) => {
          if (!cancelled) {
            setStats((prev) => {
              prevTotal.current = prev?.total_logs ?? d.total_logs;
              return d;
            });
          }
        })
        .catch(() => {});
    };
    load();
    const iv = setInterval(load, pollMs);
    return () => { cancelled = true; clearInterval(iv); };
  }, [useMock, pollMs]);

  return { stats, prevTotal: prevTotal.current };
}

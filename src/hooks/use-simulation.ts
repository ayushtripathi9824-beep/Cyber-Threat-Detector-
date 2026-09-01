import { useEffect, useRef, useCallback, useState } from "react";
import { useMutation } from "convex/react";
import { api } from "../convex/_generated/api";
import {
  generateTrafficBatch,
  detectThreats,
  cleanupWindows,
  DEFAULT_CONFIG,
  type Alert,
  type SimulationConfig,
} from "@/lib/detection-engine";

interface SimulationState {
  isRunning: boolean;
  flowsGenerated: number;
  alertsDetected: number;
  lastBatchSize: number;
  lastAlertCount: number;
  throughputPerSec: number;
  config: SimulationConfig;
}

export function useSimulation() {
  const insertFlows = useMutation(api.traffic.insertFlows);
  const insertAlerts = useMutation(api.alerts.insertAlerts);

  const [state, setState] = useState<SimulationState>({
    isRunning: false,
    flowsGenerated: 0,
    alertsDetected: 0,
    lastBatchSize: 0,
    lastAlertCount: 0,
    throughputPerSec: 0,
    config: DEFAULT_CONFIG,
  });

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const recentAlerts = useRef<Alert[]>([]);

  const tick = useCallback(async () => {
    try {
      const flows = generateTrafficBatch(DEFAULT_CONFIG);
      const alerts = detectThreats(flows);

      if (flows.length > 0) {
        await insertFlows({
          flows: flows.map((f) => ({
            ...f,
            tlsVersion: f.tlsVersion,
            ja3Hash: f.ja3Hash,
            dnsQuery: f.dnsQuery,
            dnsRecordType: f.dnsRecordType,
          })),
        });
      }

      if (alerts.length > 0) {
        await insertAlerts({
          alerts: alerts.map((a) => ({
            timestamp: a.timestamp,
            flowId: a.flowId,
            threatClass: a.threatClass,
            severity: a.severity,
            confidence: a.confidence,
            sourceIp: a.sourceIp,
            destIp: a.destIp,
            sourcePort: a.sourcePort,
            destPort: a.destPort,
            protocol: a.protocol,
            evidence: a.evidence,
          })),
        });
        recentAlerts.current = alerts;
      }

      setState((prev) => ({
        ...prev,
        flowsGenerated: prev.flowsGenerated + flows.length,
        alertsDetected: prev.alertsDetected + alerts.length,
        lastBatchSize: flows.length,
        lastAlertCount: alerts.length,
        throughputPerSec: Math.round(flows.length * 2),
      }));

      cleanupWindows();
    } catch (err) {
      console.error("[Simulation] tick error:", err);
    }
  }, [insertFlows, insertAlerts]);

  const start = useCallback(() => {
    if (intervalRef.current) return;
    setState((prev) => ({ ...prev, isRunning: true }));
    tick();
    intervalRef.current = setInterval(tick, 500);
  }, [tick]);

  const stop = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setState((prev) => ({ ...prev, isRunning: false }));
  }, []);

  useEffect(() => {
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  return {
    ...state,
    start,
    stop,
    recentAlerts: recentAlerts.current,
  };
}

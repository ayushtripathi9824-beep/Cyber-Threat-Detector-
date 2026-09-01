import { useCallback, useMemo, useState } from "react";
import { useQuery, useMutation } from "convex/react";
import { api } from "../convex/_generated/api";
import { useSimulation } from "@/hooks/use-simulation";
import { useAuth } from "@/hooks/use-auth";
import { Button } from "@/components/ui/button";
import {
  Shield,
  Play,
  Square,
  Trash2,
  AlertTriangle,
  Activity,
  Zap,
  Radio,
  Search,
  Upload,
  Lock,
  Bell,
  Clock,
  Wifi,
  Eye,
  LogOut,
} from "lucide-react";
import {
  SEVERITY_CONFIG,
  THREAT_ICONS,
  type ThreatClass,
} from "@/lib/detection-engine";
import { useNavigate } from "react-router";

// ── Threat Class Metadata ──────────────────────────────────────────

const THREAT_META: Record<
  ThreatClass,
  { icon: typeof Shield; color: string; label: string }
> = {
  "Volumetric DDoS": { icon: Zap, color: "text-red-600", label: "VOLUMETRIC DDoS" },
  "Protocol DDoS": { icon: Activity, color: "text-red-600", label: "PROTOCOL DDoS" },
  "Botnet C2 Beaconing": {
    icon: Radio,
    color: "text-orange-500",
    label: "C2 BEACONING",
  },
  "DGA Domain": { icon: AlertTriangle, color: "text-blue-600", label: "DGA DOMAIN" },
  "DNS Tunneling": { icon: Wifi, color: "text-blue-600", label: "DNS TUNNEL" },
  "Encrypted Malware": {
    icon: Lock,
    color: "text-purple-600",
    label: "ENCRYPTED MALWARE",
  },
  "Port Scanning": { icon: Search, color: "text-orange-500", label: "PORT SCAN" },
  Reconnaissance: { icon: Eye, color: "text-orange-500", label: "RECONNAISSANCE" },
  "Data Exfiltration": {
    icon: Upload,
    color: "text-red-600",
    label: "DATA EXFIL",
  },
};

// ── Dashboard Component ────────────────────────────────────────────

export default function Dashboard() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const {
    isRunning,
    flowsGenerated,
    alertsDetected,
    lastBatchSize,
    lastAlertCount,
    throughputPerSec,
    start,
    stop,
  } = useSimulation();

  const alerts = useQuery(api.alerts.listRecent, { limit: 200 });
  const stats = useQuery(api.alerts.getStats);
  const clearAlerts = useMutation(api.alerts.clearAll);
  const clearFlows = useMutation(api.traffic.clearAll);
  const acknowledgeAll = useMutation(api.alerts.acknowledgeAll);

  const [selectedThreat, setSelectedThreat] = useState<string | null>(null);
  const [showEvidence, setShowEvidence] = useState<string | null>(null);

  const handleClearAll = useCallback(async () => {
    await clearAlerts();
    await clearFlows();
  }, [clearAlerts, clearFlows]);

  const handleSignOut = useCallback(async () => {
    stop();
    await signOut();
    navigate("/");
  }, [stop, signOut, navigate]);

  const filteredAlerts = useMemo(() => {
    if (!alerts) return [];
    if (!selectedThreat) return alerts;
    return alerts.filter((a) => a.threatClass === selectedThreat);
  }, [alerts, selectedThreat]);

  const severityCounts = useMemo(() => {
    if (!stats) return { critical: 0, high: 0, medium: 0, low: 0 };
    return stats.bySeverity;
  }, [stats]);

  return (
    <div className="min-h-screen bg-[#FAFAFA]">
      {/* ── Top Bar ──────────────────────────────────────────── */}
      <header className="bg-white border-b-2 border-black sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 bg-black flex items-center justify-center">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-sm font-bold tracking-widest uppercase">
              Cyber Threat Detector
            </span>
            <span className="text-[10px] font-medium tracking-wider text-gray-400 uppercase border border-gray-200 px-2 py-0.5">
              v1.0
            </span>
          </div>

          <div className="flex items-center gap-4">
            {/* Simulation Controls */}
            <div className="flex items-center gap-2">
              {!isRunning ? (
                <Button
                  onClick={start}
                  size="sm"
                  className="bg-red-600 hover:bg-red-700 text-white rounded-none px-5 py-5 h-auto text-xs font-bold uppercase tracking-widest"
                >
                  <Play className="h-3 w-3 mr-2" />
                  Start
                </Button>
              ) : (
                <Button
                  onClick={stop}
                  size="sm"
                  variant="outline"
                  className="border-2 border-black rounded-none px-5 py-5 h-auto text-xs font-bold uppercase tracking-widest"
                >
                  <Square className="h-3 w-3 mr-2" />
                  Stop
                </Button>
              )}
            </div>

            <div className="h-6 w-px bg-gray-200" />

            <span className="text-xs text-gray-500 font-medium">
              {user?.name ?? "Operator"}
            </span>
            <Button
              onClick={handleSignOut}
              variant="ghost"
              size="sm"
              className="rounded-none text-xs"
            >
              <LogOut className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto px-6 py-6">
        {/* ── Status Strip ────────────────────────────────────── */}
        <div className="flex items-center gap-6 mb-6 py-3 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <div
              className={`h-2 w-2 rounded-full ${isRunning ? "bg-green-500 animate-pulse" : "bg-gray-300"}`}
            />
            <span className="text-[11px] font-semibold tracking-wider uppercase text-gray-500">
              {isRunning ? "Pipeline Active" : "Pipeline Inactive"}
            </span>
          </div>
          <div className="text-[11px] font-medium tracking-wider text-gray-400 uppercase">
            {throughputPerSec} flows/sec
          </div>
          <div className="text-[11px] font-medium tracking-wider text-gray-400 uppercase">
            {flowsGenerated.toLocaleString()} total flows
          </div>
          <div className="text-[11px] font-medium tracking-wider text-gray-400 uppercase">
            <Clock className="h-3 w-3 inline mr-1" />
            Last batch: {lastBatchSize} flows, {lastAlertCount} alerts
          </div>
        </div>

        {/* ── Summary Cards ───────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-0 border-2 border-black mb-6">
          <SummaryCard
            label="Total Alerts"
            value={stats?.total ?? 0}
            accent="bg-red-600"
          />
          <SummaryCard
            label="Unacknowledged"
            value={stats?.unacknowledged ?? 0}
            accent="bg-orange-500"
          />
          <SummaryCard
            label="Critical"
            value={severityCounts.critical}
            accent="bg-red-700"
          />
          <SummaryCard
            label="High"
            value={severityCounts.high}
            accent="bg-orange-600"
          />
          <SummaryCard
            label="Medium / Low"
            value={severityCounts.medium + severityCounts.low}
            accent="bg-blue-600"
            className="col-span-2 md:col-span-1"
          />
        </div>

        {/* ── Main Grid ───────────────────────────────────────── */}
        <div className="grid lg:grid-cols-[1fr_340px] gap-0 border-2 border-black">
          {/* ── Alert Feed ──────────────────────────────────────── */}
          <div className="border-r-2 border-black">
            {/* Threat Filter Tabs */}
            <div className="border-b-2 border-black bg-white overflow-x-auto">
              <div className="flex items-stretch min-w-max">
                <button
                  onClick={() => setSelectedThreat(null)}
                  className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest border-r-2 border-black transition-colors ${
                    !selectedThreat
                      ? "bg-black text-white"
                      : "bg-white text-gray-500 hover:bg-gray-50"
                  }`}
                >
                  All
                </button>
                {(
                  [
                    "Volumetric DDoS",
                    "Protocol DDoS",
                    "Botnet C2 Beaconing",
                    "DGA Domain",
                    "DNS Tunneling",
                    "Encrypted Malware",
                    "Port Scanning",
                    "Reconnaissance",
                    "Data Exfiltration",
                  ] as ThreatClass[]
                ).map((tc) => {
                  const count = (stats?.byThreatClass[tc] as number) ?? 0;
                  return (
                    <button
                      key={tc}
                      onClick={() =>
                        setSelectedThreat(
                          selectedThreat === tc ? null : tc,
                        )
                      }
                      className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest border-r-2 border-black transition-colors whitespace-nowrap ${
                        selectedThreat === tc
                          ? "bg-black text-white"
                          : "bg-white text-gray-500 hover:bg-gray-50"
                      }`}
                    >
                      {THREAT_ICONS[tc as ThreatClass] ?? "⚠"}{" "}
                      {THREAT_META[tc as ThreatClass]?.label ?? tc}
                      {count > 0 && (
                        <span
                          className={`ml-1.5 text-[9px] ${
                            selectedThreat === tc
                              ? "text-gray-400"
                              : "text-gray-400"
                          }`}
                        >
                          ({count})
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Alert List */}
            <div className="bg-[#FAFAFA] max-h-[calc(100vh-340px)] overflow-y-auto">
              {filteredAlerts.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 text-gray-400">
                  <Bell className="h-8 w-8 mb-4 text-gray-300" />
                  <p className="text-xs font-semibold uppercase tracking-widest">
                    {isRunning
                      ? "Monitoring traffic..."
                      : "No alerts — start the simulation"}
                  </p>
                </div>
              ) : (
                filteredAlerts.map((alert) => (
                  <AlertRow
                    key={alert._id}
                    alert={alert}
                    expanded={showEvidence === alert._id}
                    onToggle={() =>
                      setShowEvidence(
                        showEvidence === alert._id ? null : alert._id,
                      )
                    }
                  />
                ))
              )}
            </div>
          </div>

          {/* ── Right Sidebar ───────────────────────────────────── */}
          <div className="bg-white">
            {/* Threat Distribution */}
            <div className="p-5 border-b-2 border-black">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500 mb-4">
                Threat Distribution
              </h3>
              <div className="space-y-2">
                {stats &&
                  Object.entries(stats.byThreatClass)
                    .sort(([, a], [, b]) => (b as number) - (a as number))
                    .map(([tc, count]) => {
                      const maxCount = Math.max(
                        ...Object.values(stats.byThreatClass).map(Number),
                        1,
                      );
                      const pct = ((count as number) / maxCount) * 100;
                      return (
                        <div
                          key={tc}
                          className="flex items-center gap-3 cursor-pointer hover:bg-gray-50 px-1 py-0.5"
                          onClick={() =>
                            setSelectedThreat(
                              selectedThreat === tc ? null : tc,
                            )
                          }
                        >
                          <div className="w-1.5 h-1.5 bg-black flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-[10px] font-bold uppercase tracking-wider text-gray-700 truncate">
                                {THREAT_META[tc as ThreatClass]?.label ?? tc}
                              </span>
                              <span className="text-[10px] font-bold text-gray-400 ml-2">
                                {count as number}
                              </span>
                            </div>
                            <div className="h-1 bg-gray-100">
                              <div
                                className="h-1 bg-black transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                {(!stats || Object.keys(stats.byThreatClass).length === 0) && (
                  <div className="text-xs text-gray-400 text-center py-4">
                    No data yet
                  </div>
                )}
              </div>
            </div>

            {/* Severity Breakdown */}
            <div className="p-5 border-b-2 border-black">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500 mb-4">
                Severity Breakdown
              </h3>
              <div className="grid grid-cols-2 gap-2">
                {(["critical", "high", "medium", "low"] as const).map((sev) => (
                  <div
                    key={sev}
                    className="border border-gray-200 p-3 text-center"
                  >
                    <div className="text-2xl font-bold tracking-tight">
                      {severityCounts[sev]}
                    </div>
                    <div
                      className={`text-[9px] font-bold uppercase tracking-widest mt-1 ${SEVERITY_CONFIG[sev].textClass}`}
                    >
                      {SEVERITY_CONFIG[sev].label}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="p-5">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500 mb-4">
                Actions
              </h3>
              <div className="space-y-2">
                <Button
                  onClick={() => acknowledgeAll()}
                  variant="outline"
                  className="w-full justify-start rounded-none border-gray-300 text-xs font-semibold uppercase tracking-wider h-9"
                >
                  <Bell className="h-3 w-3 mr-2" />
                  Acknowledge All
                </Button>
                <Button
                  onClick={handleClearAll}
                  variant="outline"
                  className="w-full justify-start rounded-none border-gray-300 text-xs font-semibold uppercase tracking-wider h-9 text-red-600 hover:text-red-700"
                >
                  <Trash2 className="h-3 w-3 mr-2" />
                  Clear All Data
                </Button>
              </div>
            </div>

            {/* System Info */}
            <div className="p-5 border-t-2 border-black bg-gray-50">
              <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500 mb-3">
                System Info
              </h3>
              <div className="space-y-1.5 text-[10px] font-medium tracking-wider text-gray-400 uppercase">
                <div className="flex justify-between">
                  <span>Pipeline</span>
                  <span className="text-black">v1.0</span>
                </div>
                <div className="flex justify-between">
                  <span>Ingest Mode</span>
                  <span className="text-black">Read-Only</span>
                </div>
                <div className="flex justify-between">
                  <span>Decryption</span>
                  <span className="text-black">None</span>
                </div>
                <div className="flex justify-between">
                  <span>Throughput</span>
                  <span className="text-black">
                    {throughputPerSec} flows/s
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

// ── Sub-Components ─────────────────────────────────────────────────

function SummaryCard({
  label,
  value,
  accent,
  className = "",
}: {
  label: string;
  value: number;
  accent: string;
  className?: string;
}) {
  return (
    <div className={`bg-white p-5 ${className}`}>
      <div className="h-1 w-full mb-4">
        <div className={`h-full ${accent} w-full`} />
      </div>
      <div className="text-3xl font-bold tracking-tight">{value}</div>
      <div className="text-[10px] font-bold uppercase tracking-[0.15em] text-gray-500 mt-1">
        {label}
      </div>
    </div>
  );
}

function AlertRow({
  alert,
  expanded,
  onToggle,
}: {
  alert: {
    _id: string;
    _creationTime: number;
    timestamp: number;
    flowId: string;
    threatClass: string;
    severity: string;
    confidence: number;
    sourceIp: string;
    destIp: string;
    sourcePort: number;
    destPort: number;
    protocol: string;
    evidence: string;
    acknowledged: boolean;
  };
  expanded: boolean;
  onToggle: () => void;
}) {
  const sevConfig =
    SEVERITY_CONFIG[alert.severity as keyof typeof SEVERITY_CONFIG];
  const threatMeta =
    THREAT_META[alert.threatClass as ThreatClass];

  let evidenceParsed: Record<string, unknown> = {};
  try {
    evidenceParsed = JSON.parse(alert.evidence);
  } catch {
    // leave empty
  }

  const timeStr = new Date(alert.timestamp).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div
      className={`border-b border-gray-200 cursor-pointer transition-colors ${
        alert.acknowledged
          ? "bg-gray-50 opacity-60"
          : "bg-white hover:bg-gray-50"
      }`}
      onClick={onToggle}
    >
      <div className="px-4 py-3 flex items-start gap-3">
        {/* Severity indicator */}
        <div
          className="w-1 self-stretch flex-shrink-0 mt-1"
          style={{ backgroundColor: sevConfig?.color ?? "#999" }}
        />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-gray-400">
              {timeStr}
            </span>
            <span
              className="text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5"
              style={{
                backgroundColor: sevConfig?.color ?? "#999",
                color: "white",
              }}
            >
              {sevConfig?.label ?? alert.severity}
            </span>
            <span className="text-[10px] font-medium text-gray-400">
              {(alert.confidence * 100).toFixed(0)}% confidence
            </span>
          <

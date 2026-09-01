// ═══════════════════════════════════════════════════════════════════
// Cyber Threat Detector — Detection Engine v1.0
// ═══════════════════════════════════════════════════════════════════

// ── Types ──────────────────────────────────────────────────────────

export interface FlowRecord {
  timestamp: number;
  flowId: string;
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  protocol: string;
  bytesForward: number;
  bytesBackward: number;
  packetsForward: number;
  packetsBackward: number;
  duration: number;
  flags: string;
  tlsVersion?: string;
  ja3Hash?: string;
  dnsQuery?: string;
  dnsRecordType?: string;
}

export type Severity = "critical" | "high" | "medium" | "low";
export type ThreatClass =
  | "Volumetric DDoS"
  | "Protocol DDoS"
  | "Botnet C2 Beaconing"
  | "DGA Domain"
  | "DNS Tunneling"
  | "Encrypted Malware"
  | "Port Scanning"
  | "Reconnaissance"
  | "Data Exfiltration";

export interface Alert {
  timestamp: number;
  flowId: string;
  threatClass: ThreatClass;
  severity: Severity;
  confidence: number;
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  protocol: string;
  evidence: string;
}

// ── IP Generation Utilities ────────────────────────────────────────

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIp(): string {
  return `${randInt(1, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
}

function randomPrivateIp(): string {
  const subnets = [
    () => `10.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
    () => `172.${randInt(16, 31)}.${randInt(0, 255)}.${randInt(1, 254)}`,
    () => `192.168.${randInt(0, 255)}.${randInt(1, 254)}`,
  ];
  return subnets[randInt(0, 2)]();
}

let flowCounter = 0;
function makeFlowId(): string {
  return `FLOW-${Date.now().toString(36)}-${(flowCounter++).toString(36).padStart(4, "0")}`;
}

const MALWARE_JA3_HASHES = [
  "e7d705a3286e19ea42f587b344ee6865",
  "b32309a26951912be7dba376398abc3b",
  "72a589da586844d7f0818ce684948eea",
  "9e10692f1b7f78228b2d4e424db3a98c",
  "3b5074b1b5d032e5620f69f9f700ff0e",
];

const DGA_DOMAINS = [
  "xjkqmwhe.shop",
  "a3f9b2c1d4e5.net",
  "qwertyuiop12345.org",
  "zxcvbnmasdfg.info",
  "mkilopoiuytrewq.com",
  "plokmijnbhuvgfds.biz",
  "asertyuioplkjhgf.xyz",
  "zamowaniexxvp.com",
  "bwtokzmwepfd.com",
  "longshadowserverhost.top",
  "cnxievqxsmdb.com",
  "dfrtghjkloiuytr.me",
  "a1b2c3d4e5f6.click",
  "xyzqwerty12345.cam",
  "randomstring1337.dev",
];

const DNS_TUNNEL_DOMAINS = [
  "aGVsbG8gd29ybGQ.record.tunnel.evil.com",
  "dGhpcyBpcyBhIHRlc3Q.data.exfil.net",
  "c2NyeXB0ZWQgbWVzc2FnZQ.c2.tunnel.bad",
  "SGVsbG8gV29ybGQ.dns.tunnel.sus",
  "YmFzZTY0IGVuY29kZWQ.query.tun.evil",
  "YWJjZGVmZ2hpamtsbW5vcA.dns.c2.evil",
  "bXlzZWNyZXRkYXRh.b64.tunnel.io",
  "cGFzc3dvcmQxMjM.c2record.evil.com",
];

const C2_SERVERS = [
  "45.33.32.156",
  "198.51.100.42",
  "203.0.113.77",
  "192.0.2.100",
  "100.26.91.12",
];

const NORMAL_PORTS = [80, 443, 53, 8080, 8443, 22, 21, 25, 110, 143, 993, 995, 3306, 5432, 6379];

// ── Traffic Simulator ──────────────────────────────────────────────

export interface SimulationConfig {
  ddosRate: number;
  c2Rate: number;
  dgaRate: number;
  dnsTunnelRate: number;
  malwareRate: number;
  scanRate: number;
  exfilRate: number;
  benignRate: number;
}

export const DEFAULT_CONFIG: SimulationConfig = {
  ddosRate: 0.08,
  c2Rate: 0.06,
  dgaRate: 0.05,
  dnsTunnelRate: 0.04,
  malwareRate: 0.05,
  scanRate: 0.06,
  exfilRate: 0.05,
  benignRate: 3,
};

const flowWindow: Map<string, FlowRecord[]> = new Map();
const dnsWindow: { timestamp: number; query: string; sourceIp: string }[] = [];
const scanTracker: Map<string, Set<string>> = new Map();

const alertedKeys = new Set<string>();
let lastAlertCleanup = Date.now();

function generateBenignFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  const dstIp = randomIp();
  const proto = Math.random() > 0.3 ? "TCP" : "UDP";
  const dstPort = NORMAL_PORTS[randInt(0, NORMAL_PORTS.length - 1)];

  const isTLS = dstPort === 443 || dstPort === 8443;
  const bytesF = randInt(200, 15000);
  const bytesB = randInt(200, 15000);
  const pktsF = Math.ceil(bytesF / 1400);
  const pktsB = Math.ceil(bytesB / 1400);

  const flags = proto === "TCP" ? pickTcpFlags("normal") : "UDP";

  const flow: FlowRecord = {
    timestamp: now + randInt(0, 100),
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: dstIp,
    sourcePort: randInt(49152, 65535),
    destPort: dstPort,
    protocol: proto,
    bytesForward: bytesF,
    bytesBackward: bytesB,
    packetsForward: pktsF,
    packetsBackward: pktsB,
    duration: randInt(1, 30000),
    flags,
  };

  if (isTLS) {
    flow.tlsVersion = Math.random() > 0.3 ? "TLSv1.3" : "TLSv1.2";
    flow.ja3Hash = "a" + randInt(100000000, 999999999).toString(16) + "f";
  }

  if (dstPort === 53) {
    const query = generateNormalDnsQuery();
    flow.dnsQuery = query;
    flow.dnsRecordType = pickRandom(["A", "AAAA", "CNAME", "MX"]);
  }

  return flow;
}

function pickTcpFlags(type: "normal" | "synFlood"): string {
  if (type === "synFlood") return "SYN";
  const patterns = ["SYN,ACK", "ACK", "PSH,ACK", "FIN,ACK", "RST,ACK", "ACK"];
  return pickRandom(patterns);
}

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateNormalDnsQuery(): string {
  const domains = [
    "google.com", "github.com", "cloudflare.com", "amazon.com",
    "microsoft.com", "apple.com", "facebook.com", "twitter.com",
    "reddit.com", "wikipedia.org", "stackoverflow.com", "npmjs.com",
    "cdn.jsdelivr.net", "fonts.googleapis.com", "api.openai.com",
  ];
  return pickRandom(domains);
}

function generateDgaDomain(): string {
  return pickRandom(DGA_DOMAINS);
}

function generateDnsTunnelDomain(): string {
  return pickRandom(DNS_TUNNEL_DOMAINS);
}

// ── Attack Generators ──────────────────────────────────────────────

function generateDdosFlow(now: number, type: "volumetric" | "protocol"): FlowRecord {
  const srcIp = randomIp();
  const dstIp = randomPrivateIp();
  const isTcp = type === "protocol";

  if (isTcp) {
    return {
      timestamp: now + randInt(0, 50),
      flowId: makeFlowId(),
      sourceIp: srcIp,
      destIp: dstIp,
      sourcePort: randInt(1, 65535),
      destPort: pickRandom([80, 443, 8080, 22]),
      protocol: "TCP",
      bytesForward: randInt(40, 60),
      bytesBackward: 0,
      packetsForward: 1,
      packetsBackward: 0,
      duration: 0,
      flags: "SYN",
    };
  }

  return {
    timestamp: now + randInt(0, 50),
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: dstIp,
    sourcePort: randInt(1, 65535),
    destPort: pickRandom([53, 123, 1900, 389, 520, 11211]),
    protocol: "UDP",
    bytesForward: randInt(40, 100),
    bytesBackward: randInt(2000, 50000),
    packetsForward: 1,
    packetsBackward: randInt(5, 200),
    duration: 0,
    flags: "UDP",
  };
}

function generateC2BeaconFlow(now: number, srcIp: string, c2Server: string): FlowRecord {
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: c2Server,
    sourcePort: randInt(49152, 65535),
    destPort: pickRandom([443, 8443, 80, 4444, 8080]),
    protocol: "TCP",
    bytesForward: randInt(64, 512),
    bytesBackward: randInt(128, 1024),
    packetsForward: randInt(1, 3),
    packetsBackward: randInt(1, 3),
    duration: randInt(100, 2000),
    flags: "PSH,ACK",
    tlsVersion: Math.random() > 0.5 ? "TLSv1.3" : "TLSv1.2",
    ja3Hash: MALWARE_JA3_HASHES[randInt(0, MALWARE_JA3_HASHES.length - 1)],
  };
}

function generateDgaFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  const query = generateDgaDomain();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: randomIp(),
    sourcePort: randInt(49152, 65535),
    destPort: 53,
    protocol: "UDP",
    bytesForward: randInt(40, 80),
    bytesBackward: randInt(200, 800),
    packetsForward: 1,
    packetsBackward: 1,
    duration: randInt(1, 100),
    flags: "UDP",
    dnsQuery: query,
    dnsRecordType: "A",
  };
}

function generateDnsTunnelFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  const query = generateDnsTunnelDomain();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: randomIp(),
    sourcePort: randInt(49152, 65535),
    destPort: 53,
    protocol: "UDP",
    bytesForward: randInt(100, 500),
    bytesBackward: randInt(200, 4000),
    packetsForward: randInt(1, 3),
    packetsBackward: randInt(1, 5),
    duration: randInt(1, 500),
    flags: "UDP",
    dnsQuery: query,
    dnsRecordType: pickRandom(["TXT", "CNAME", "NULL", "MX"]),
  };
}

function generateMalwareFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: pickRandom(C2_SERVERS),
    sourcePort: randInt(49152, 65535),
    destPort: pickRandom([443, 8443, 4444, 5555, 9999]),
    protocol: "TCP",
    bytesForward: randInt(500, 5000),
    bytesBackward: randInt(500, 10000),
    packetsForward: randInt(3, 20),
    packetsBackward: randInt(3, 20),
    duration: randInt(5000, 60000),
    flags: "PSH,ACK",
    tlsVersion: Math.random() > 0.4 ? "TLSv1.2" : "TLSv1.3",
    ja3Hash: pickRandom(MALWARE_JA3_HASHES),
  };
}

function generateScanFlow(now: number, scanState: { srcIp: string; targetHost: string; portIndex: number }): FlowRecord {
  const port = randInt(1, 65535);
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: scanState.srcIp,
    destIp: scanState.targetHost,
    sourcePort: randInt(49152, 65535),
    destPort: port,
    protocol: Math.random() > 0.5 ? "TCP" : "UDP",
    bytesForward: randInt(40, 60),
    bytesBackward: Math.random() > 0.7 ? randInt(40, 200) : 0,
    packetsForward: 1,
    packetsBackward: Math.random() > 0.7 ? 1 : 0,
    duration: randInt(0, 50),
    flags: pickRandom(["SYN", "SYN", "SYN", "ACK"]),
  };
}

function generateExfilFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: randomIp(),
    sourcePort: randInt(49152, 65535),
    destPort: pickRandom([443, 444, 8443, 22, 993]),
    protocol: Math.random() > 0.3 ? "TCP" : "UDP",
    bytesForward: randInt(50000, 500000),
    bytesBackward: randInt(100, 800),
    packetsForward: randInt(50, 500),
    packetsBackward: randInt(1, 10),
    duration: randInt(5000, 120000),
    flags: "PSH,ACK",
    tlsVersion: "TLSv1.3",
    ja3Hash: "a" + randInt(100000000, 999999999).toString(16) + "f",
  };
}

// ── Detection Algorithms ───────────────────────────────────────────

function addToWindow(flow: FlowRecord): void {
  const key = `${flow.sourceIp}:${flow.destIp}:${flow.destPort}`;
  if (!flowWindow.has(key)) flowWindow.set(key, []);
  const arr = flowWindow.get(key)!;
  arr.push(flow);
  const cutoff = flow.timestamp - 60000;
  while (arr.length > 0 && arr[0].timestamp < cutoff) arr.shift();
}

function detectDdos(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];
  const window = 5000;
  const now = Date.now();

  const recentFlows = flows.filter((f) => now - f.timestamp < window);
  const byDst = new Map<string, FlowRecord[]>();
  for (const f of recentFlows) {
    if (!byDst.has(f.destIp)) byDst.set(f.destIp, []);
    byDst.get(f.destIp)!.push(f);
  }

  for (const [dstIp, dstFlows] of byDst) {
    if (dstFlows.length < 30) continue;

    const sourceIps = new Set(dstFlows.map((f) => f.sourceIp));
    const srcEntropy = Math.log2(sourceIps.size + 1);
    const synCount = dstFlows.filter((f) => f.flags.includes("SYN") && !f.flags.includes("ACK")).length;
    const synRatio = synCount / dstFlows.length;
    const noResponse = dstFlows.filter((f) => f.packetsBackward === 0).length;
    const noRespRatio = noResponse / dstFlows.length;
    const totalBandwidth = dstFlows.reduce((s, f) => s + f.bytesForward + f.bytesBackward, 0);

    if (dstFlows.length > 50 && sourceIps.size > 10 && synRatio > 0.6 && noRespRatio > 0.5) {
      const confidence = Math.min(0.99, 0.5 + (dstFlows.length / 200) * 0.2 + srcEntropy * 0.05 + synRatio * 0.15);
      alerts.push({
        timestamp: now,
        flowId: dstFlows[0].flowId,
        threatClass: "Volumetric DDoS",
        severity: dstFlows.length > 100 ? "critical" : "high",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: `${sourceIps.size} unique sources`,
        destIp: dstIp,
        sourcePort: 0,
        destPort: dstFlows[0].destPort,
        protocol: "TCP/UDP",
        evidence: JSON.stringify({
          flowsPerSec: Math.round(dstFlows.length / 5),
          uniqueSources: sourceIps.size,
          synRatio: Math.round(synRatio * 100) + "%",
          noResponseRatio: Math.round(noRespRatio * 100) + "%",
          srcEntropy: Math.round(srcEntropy * 100) / 100,
          totalBandwidthMB: Math.round((totalBandwidth / 1048576) * 10) / 10,
        }),
      });
    }

    if (synCount > 30 && synRatio > 0.8 && noRespRatio > 0.7) {
      const confidence = Math.min(0.98, 0.6 + synRatio * 0.2 + noRespRatio * 0.15);
      alerts.push({
        timestamp: now,
        flowId: dstFlows[0].flowId,
        threatClass: "Protocol DDoS",
        severity: synCount > 80 ? "critical" : "high",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: `${sourceIps.size} unique sources`,
        destIp: dstIp,
        sourcePort: 0,
        destPort: dstFlows[0].destPort,
        protocol: "TCP",
        evidence: JSON.stringify({
          synFloodCount: synCount,
          synRatio: Math.round(synRatio * 100) + "%",
          uniqueSources: sourceIps.size,
          pattern: "SYN-only, no ACK responses — handshake never completes",
        }),
      });
    }
  }

  return alerts;
}

function detectC2Beaconing(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];

  const pairs = new Map<string, FlowRecord[]>();
  for (const f of flows) {
    const key = `${f.sourceIp}:${f.destIp}`;
    if (!pairs.has(key)) pairs.set(key, []);
    pairs.get(key)!.push(f);
  }

  for (const [key, pairFlows] of pairs) {
    if (pairFlows.length < 5) continue;

    pairFlows.sort((a, b) => a.timestamp - b.timestamp);

    const intervals: number[] = [];
    for (let i = 1; i < pairFlows.length; i++) {
      intervals.push(pairFlows[i].timestamp - pairFlows[i - 1].timestamp);
    }

    if (intervals.length < 3) continue;

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length;
    const cv = Math.sqrt(variance) / mean;

    const sizes = pairFlows.map((f) => f.bytesForward);
    const sizeMean = sizes.reduce((a, b) => a + b, 0) / sizes.length;
    const sizeVariance = sizes.reduce((s, v) => s + (v - sizeMean) ** 2, 0) / sizes.length;
    const sizeCv = Math.sqrt(sizeVariance) / (sizeMean || 1);

    if (cv < 0.4 && pairFlows.length >= 5 && sizeMean < 600 && sizeCv < 0.5) {
      const intervalSec = Math.round(mean / 1000);
      const confidence = Math.min(
        0.97,
        0.5 + (1 - cv) * 0.2 + (pairFlows.length / 20) * 0.1 + (1 - sizeCv) * 0.1,
      );

      alerts.push({
        timestamp: Date.now(),
        flowId: pairFlows[0].flowId,
        threatClass: "Botnet C2 Beaconing",
        severity: intervalSec < 60 ? "critical" : intervalSec < 300 ? "high" : "medium",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: pairFlows[0].sourceIp,
        destIp: pairFlows[0].destIp,
        sourcePort: pairFlows[0].sourcePort,
        destPort: pairFlows[0].destPort,
        protocol: pairFlows[0].protocol,
        evidence: JSON.stringify({
          beaconCount: pairFlows.length,
          avgIntervalSec: intervalSec,
          cvOfIntervals: Math.round(cv * 100) / 100,
          avgPacketSize: Math.round(sizeMean),
          sizeRegularity: Math.round((1 - sizeCv) * 100) + "%",
          tlsVersion: pairFlows[0].tlsVersion,
          ja3Hash: pairFlows[0].ja3Hash,
        }),
      });
    }
  }

  return alerts;
}

function detectDGA(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];

  for (const flow of flows) {
    if (!flow.dnsQuery) continue;

    const query = flow.dnsQuery.split(".")[0];
    if (!query || query.length < 5) continue;

    const freq = new Map<string, number>();
    for (const c of query) {
      freq.set(c, (freq.get(c) ?? 0) + 1);
    }
    let entropy = 0;
    for (const [, count] of freq) {
      const p = count / query.length;
      entropy -= p * Math.log2(p);
    }

    const hasVowelRun = /[aeiou]{3,}/i.test(query);
    const consonantClusters = (query.match(/[^aeiou]{4,}/gi) || []).length;
    const digitRatio = (query.match(/\d/g) || []).length / query.length;
    const isHighEntropy = entropy > 3.0;
    const isLongName = query.length > 12;
    const hasNoVowelRun = !hasVowelRun;
    const hasDigitNoise = digitRatio > 0.15;

    const suspiciousScore =
      (isHighEntropy ? 0.3 : 0) +
      (isLongName ? 0.2 : 0) +
      (hasNoVowelRun ? 0.15 : 0) +
      (hasDigitNoise ? 0.15 : 0) +
      (consonantClusters > 2 ? 0.1 : 0) +
      (query.length > 20 ? 0.1 : 0);

    if (suspiciousScore > 0.6) {
      const confidence = Math.min(0.95, suspiciousScore);
      alerts.push({
        timestamp: flow.timestamp,
        flowId: flow.flowId,
        threatClass: "DGA Domain",
        severity: confidence > 0.8 ? "high" : "medium",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: flow.sourceIp,
        destIp: flow.destIp,
        sourcePort: flow.sourcePort,
        destPort: flow.destPort,
        protocol: flow.protocol,
        evidence: JSON.stringify({
          query: flow.dnsQuery,
          domainLength: query.length,
          entropy: Math.round(entropy * 100) / 100,
          vowelRun: hasVowelRun,
          consonantClusters,
          digitRatio: Math.round(digitRatio * 100) + "%",
          recordType: flow.dnsRecordType,
        }),
      });
    }
  }

  return alerts;
}

function detectDnsTunneling(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];

  for (const flow of flows) {
    if (!flow.dnsQuery || flow.destPort !== 53) continue;

    const queryLen = flow.dnsQuery.length;
    const bytesRatio = flow.bytesForward / (flow.bytesBackward || 1);
    const isTxtOrCname = ["TXT", "CNAME", "NULL", "MX"].includes(flow.dnsRecordType ?? "");

    const tunnelScore =
      (queryLen > 50 ? 0.3 : queryLen > 30 ? 0.15 : 0) +
      (flow.bytesForward > 150 ? 0.25 : 0) +
      (flow.bytesBackward > 500 ? 0.2 : 0) +
      (isTxtOrCname ? 0.15 : 0) +
      (bytesRatio > 0.3 ? 0.1 : 0);

    const b64Pattern = /^[A-Za-z0-9+/=_-]+$/;
    const subdomain = flow.dnsQuery.split(".")[0];
    if (subdomain && b64Pattern.test(subdomain) && subdomain.length > 20) {
      alerts.push({
        timestamp: flow.timestamp,
        flowId: flow.flowId,
        threatClass: "DNS Tunneling",
        severity: "high",
        confidence: Math.min(0.95, tunnelScore + 0.2),
        sourceIp: flow.sourceIp,
        destIp: flow.destIp,
        sourcePort: flow.sourcePort,
        destPort: flow.destPort,
        protocol: flow.protocol,
        evidence: JSON.stringify({
          query: flow.dnsQuery,
          queryLength: queryLen,
          subdomainLength: subdomain.length,
          bytesForward: flow.bytesForward,
          bytesBackward: flow.bytesBackward,
          recordType: flow.dnsRecordType,
          suspectedEncoding: "base64",
        }),
      });
    } else if (tunnelScore > 0.6) {
      alerts.push({
        timestamp: flow.timestamp,
        flowId: flow.flowId,
        threatClass: "DNS Tunneling",
        severity: tunnelScore >// ═══════════════════════════════════════════════════════════════════
// Cyber Threat Detector — Detection Engine v1.0
// ═══════════════════════════════════════════════════════════════════

// ── Types ──────────────────────────────────────────────────────────

export interface FlowRecord {
  timestamp: number;
  flowId: string;
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  protocol: string;
  bytesForward: number;
  bytesBackward: number;
  packetsForward: number;
  packetsBackward: number;
  duration: number;
  flags: string;
  tlsVersion?: string;
  ja3Hash?: string;
  dnsQuery?: string;
  dnsRecordType?: string;
}

export type Severity = "critical" | "high" | "medium" | "low";
export type ThreatClass =
  | "Volumetric DDoS"
  | "Protocol DDoS"
  | "Botnet C2 Beaconing"
  | "DGA Domain"
  | "DNS Tunneling"
  | "Encrypted Malware"
  | "Port Scanning"
  | "Reconnaissance"
  | "Data Exfiltration";

export interface Alert {
  timestamp: number;
  flowId: string;
  threatClass: ThreatClass;
  severity: Severity;
  confidence: number;
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  protocol: string;
  evidence: string;
}

// ── IP Generation Utilities ────────────────────────────────────────

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIp(): string {
  return `${randInt(1, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
}

function randomPrivateIp(): string {
  const subnets = [
    () => `10.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
    () => `172.${randInt(16, 31)}.${randInt(0, 255)}.${randInt(1, 254)}`,
    () => `192.168.${randInt(0, 255)}.${randInt(1, 254)}`,
  ];
  return subnets[randInt(0, 2)]();
}

let flowCounter = 0;
function makeFlowId(): string {
  return `FLOW-${Date.now().toString(36)}-${(flowCounter++).toString(36).padStart(4, "0")}`;
}

const MALWARE_JA3_HASHES = [
  "e7d705a3286e19ea42f587b344ee6865",
  "b32309a26951912be7dba376398abc3b",
  "72a589da586844d7f0818ce684948eea",
  "9e10692f1b7f78228b2d4e424db3a98c",
  "3b5074b1b5d032e5620f69f9f700ff0e",
];

const DGA_DOMAINS = [
  "xjkqmwhe.shop",
  "a3f9b2c1d4e5.net",
  "qwertyuiop12345.org",
  "zxcvbnmasdfg.info",
  "mkilopoiuytrewq.com",
  "plokmijnbhuvgfds.biz",
  "asertyuioplkjhgf.xyz",
  "zamowaniexxvp.com",
  "bwtokzmwepfd.com",
  "longshadowserverhost.top",
  "cnxievqxsmdb.com",
  "dfrtghjkloiuytr.me",
  "a1b2c3d4e5f6.click",
  "xyzqwerty12345.cam",
  "randomstring1337.dev",
];

const DNS_TUNNEL_DOMAINS = [
  "aGVsbG8gd29ybGQ.record.tunnel.evil.com",
  "dGhpcyBpcyBhIHRlc3Q.data.exfil.net",
  "c2NyeXB0ZWQgbWVzc2FnZQ.c2.tunnel.bad",
  "SGVsbG8gV29ybGQ.dns.tunnel.sus",
  "YmFzZTY0IGVuY29kZWQ.query.tun.evil",
  "YWJjZGVmZ2hpamtsbW5vcA.dns.c2.evil",
  "bXlzZWNyZXRkYXRh.b64.tunnel.io",
  "cGFzc3dvcmQxMjM.c2record.evil.com",
];

const C2_SERVERS = [
  "45.33.32.156",
  "198.51.100.42",
  "203.0.113.77",
  "192.0.2.100",
  "100.26.91.12",
];

const NORMAL_PORTS = [80, 443, 53, 8080, 8443, 22, 21, 25, 110, 143, 993, 995, 3306, 5432, 6379];

// ── Traffic Simulator ──────────────────────────────────────────────

export interface SimulationConfig {
  ddosRate: number;
  c2Rate: number;
  dgaRate: number;
  dnsTunnelRate: number;
  malwareRate: number;
  scanRate: number;
  exfilRate: number;
  benignRate: number;
}

export const DEFAULT_CONFIG: SimulationConfig = {
  ddosRate: 0.08,
  c2Rate: 0.06,
  dgaRate: 0.05,
  dnsTunnelRate: 0.04,
  malwareRate: 0.05,
  scanRate: 0.06,
  exfilRate: 0.05,
  benignRate: 3,
};

const flowWindow: Map<string, FlowRecord[]> = new Map();
const dnsWindow: { timestamp: number; query: string; sourceIp: string }[] = [];
const scanTracker: Map<string, Set<string>> = new Map();

const alertedKeys = new Set<string>();
let lastAlertCleanup = Date.now();

function generateBenignFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  const dstIp = randomIp();
  const proto = Math.random() > 0.3 ? "TCP" : "UDP";
  const dstPort = NORMAL_PORTS[randInt(0, NORMAL_PORTS.length - 1)];

  const isTLS = dstPort === 443 || dstPort === 8443;
  const bytesF = randInt(200, 15000);
  const bytesB = randInt(200, 15000);
  const pktsF = Math.ceil(bytesF / 1400);
  const pktsB = Math.ceil(bytesB / 1400);

  const flags = proto === "TCP" ? pickTcpFlags("normal") : "UDP";

  const flow: FlowRecord = {
    timestamp: now + randInt(0, 100),
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: dstIp,
    sourcePort: randInt(49152, 65535),
    destPort: dstPort,
    protocol: proto,
    bytesForward: bytesF,
    bytesBackward: bytesB,
    packetsForward: pktsF,
    packetsBackward: pktsB,
    duration: randInt(1, 30000),
    flags,
  };

  if (isTLS) {
    flow.tlsVersion = Math.random() > 0.3 ? "TLSv1.3" : "TLSv1.2";
    flow.ja3Hash = "a" + randInt(100000000, 999999999).toString(16) + "f";
  }

  if (dstPort === 53) {
    const query = generateNormalDnsQuery();
    flow.dnsQuery = query;
    flow.dnsRecordType = pickRandom(["A", "AAAA", "CNAME", "MX"]);
  }

  return flow;
}

function pickTcpFlags(type: "normal" | "synFlood"): string {
  if (type === "synFlood") return "SYN";
  const patterns = ["SYN,ACK", "ACK", "PSH,ACK", "FIN,ACK", "RST,ACK", "ACK"];
  return pickRandom(patterns);
}

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateNormalDnsQuery(): string {
  const domains = [
    "google.com", "github.com", "cloudflare.com", "amazon.com",
    "microsoft.com", "apple.com", "facebook.com", "twitter.com",
    "reddit.com", "wikipedia.org", "stackoverflow.com", "npmjs.com",
    "cdn.jsdelivr.net", "fonts.googleapis.com", "api.openai.com",
  ];
  return pickRandom(domains);
}

function generateDgaDomain(): string {
  return pickRandom(DGA_DOMAINS);
}

function generateDnsTunnelDomain(): string {
  return pickRandom(DNS_TUNNEL_DOMAINS);
}

// ── Attack Generators ──────────────────────────────────────────────

function generateDdosFlow(now: number, type: "volumetric" | "protocol"): FlowRecord {
  const srcIp = randomIp();
  const dstIp = randomPrivateIp();
  const isTcp = type === "protocol";

  if (isTcp) {
    return {
      timestamp: now + randInt(0, 50),
      flowId: makeFlowId(),
      sourceIp: srcIp,
      destIp: dstIp,
      sourcePort: randInt(1, 65535),
      destPort: pickRandom([80, 443, 8080, 22]),
      protocol: "TCP",
      bytesForward: randInt(40, 60),
      bytesBackward: 0,
      packetsForward: 1,
      packetsBackward: 0,
      duration: 0,
      flags: "SYN",
    };
  }

  return {
    timestamp: now + randInt(0, 50),
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: dstIp,
    sourcePort: randInt(1, 65535),
    destPort: pickRandom([53, 123, 1900, 389, 520, 11211]),
    protocol: "UDP",
    bytesForward: randInt(40, 100),
    bytesBackward: randInt(2000, 50000),
    packetsForward: 1,
    packetsBackward: randInt(5, 200),
    duration: 0,
    flags: "UDP",
  };
}

function generateC2BeaconFlow(now: number, srcIp: string, c2Server: string): FlowRecord {
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: c2Server,
    sourcePort: randInt(49152, 65535),
    destPort: pickRandom([443, 8443, 80, 4444, 8080]),
    protocol: "TCP",
    bytesForward: randInt(64, 512),
    bytesBackward: randInt(128, 1024),
    packetsForward: randInt(1, 3),
    packetsBackward: randInt(1, 3),
    duration: randInt(100, 2000),
    flags: "PSH,ACK",
    tlsVersion: Math.random() > 0.5 ? "TLSv1.3" : "TLSv1.2",
    ja3Hash: MALWARE_JA3_HASHES[randInt(0, MALWARE_JA3_HASHES.length - 1)],
  };
}

function generateDgaFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  const query = generateDgaDomain();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: randomIp(),
    sourcePort: randInt(49152, 65535),
    destPort: 53,
    protocol: "UDP",
    bytesForward: randInt(40, 80),
    bytesBackward: randInt(200, 800),
    packetsForward: 1,
    packetsBackward: 1,
    duration: randInt(1, 100),
    flags: "UDP",
    dnsQuery: query,
    dnsRecordType: "A",
  };
}

function generateDnsTunnelFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  const query = generateDnsTunnelDomain();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: randomIp(),
    sourcePort: randInt(49152, 65535),
    destPort: 53,
    protocol: "UDP",
    bytesForward: randInt(100, 500),
    bytesBackward: randInt(200, 4000),
    packetsForward: randInt(1, 3),
    packetsBackward: randInt(1, 5),
    duration: randInt(1, 500),
    flags: "UDP",
    dnsQuery: query,
    dnsRecordType: pickRandom(["TXT", "CNAME", "NULL", "MX"]),
  };
}

function generateMalwareFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: pickRandom(C2_SERVERS),
    sourcePort: randInt(49152, 65535),
    destPort: pickRandom([443, 8443, 4444, 5555, 9999]),
    protocol: "TCP",
    bytesForward: randInt(500, 5000),
    bytesBackward: randInt(500, 10000),
    packetsForward: randInt(3, 20),
    packetsBackward: randInt(3, 20),
    duration: randInt(5000, 60000),
    flags: "PSH,ACK",
    tlsVersion: Math.random() > 0.4 ? "TLSv1.2" : "TLSv1.3",
    ja3Hash: pickRandom(MALWARE_JA3_HASHES),
  };
}

function generateScanFlow(now: number, scanState: { srcIp: string; targetHost: string; portIndex: number }): FlowRecord {
  const port = randInt(1, 65535);
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: scanState.srcIp,
    destIp: scanState.targetHost,
    sourcePort: randInt(49152, 65535),
    destPort: port,
    protocol: Math.random() > 0.5 ? "TCP" : "UDP",
    bytesForward: randInt(40, 60),
    bytesBackward: Math.random() > 0.7 ? randInt(40, 200) : 0,
    packetsForward: 1,
    packetsBackward: Math.random() > 0.7 ? 1 : 0,
    duration: randInt(0, 50),
    flags: pickRandom(["SYN", "SYN", "SYN", "ACK"]),
  };
}

function generateExfilFlow(now: number): FlowRecord {
  const srcIp = randomPrivateIp();
  return {
    timestamp: now,
    flowId: makeFlowId(),
    sourceIp: srcIp,
    destIp: randomIp(),
    sourcePort: randInt(49152, 65535),
    destPort: pickRandom([443, 444, 8443, 22, 993]),
    protocol: Math.random() > 0.3 ? "TCP" : "UDP",
    bytesForward: randInt(50000, 500000),
    bytesBackward: randInt(100, 800),
    packetsForward: randInt(50, 500),
    packetsBackward: randInt(1, 10),
    duration: randInt(5000, 120000),
    flags: "PSH,ACK",
    tlsVersion: "TLSv1.3",
    ja3Hash: "a" + randInt(100000000, 999999999).toString(16) + "f",
  };
}

// ── Detection Algorithms ───────────────────────────────────────────

function addToWindow(flow: FlowRecord): void {
  const key = `${flow.sourceIp}:${flow.destIp}:${flow.destPort}`;
  if (!flowWindow.has(key)) flowWindow.set(key, []);
  const arr = flowWindow.get(key)!;
  arr.push(flow);
  const cutoff = flow.timestamp - 60000;
  while (arr.length > 0 && arr[0].timestamp < cutoff) arr.shift();
}

function detectDdos(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];
  const window = 5000;
  const now = Date.now();

  const recentFlows = flows.filter((f) => now - f.timestamp < window);
  const byDst = new Map<string, FlowRecord[]>();
  for (const f of recentFlows) {
    if (!byDst.has(f.destIp)) byDst.set(f.destIp, []);
    byDst.get(f.destIp)!.push(f);
  }

  for (const [dstIp, dstFlows] of byDst) {
    if (dstFlows.length < 30) continue;

    const sourceIps = new Set(dstFlows.map((f) => f.sourceIp));
    const srcEntropy = Math.log2(sourceIps.size + 1);
    const synCount = dstFlows.filter((f) => f.flags.includes("SYN") && !f.flags.includes("ACK")).length;
    const synRatio = synCount / dstFlows.length;
    const noResponse = dstFlows.filter((f) => f.packetsBackward === 0).length;
    const noRespRatio = noResponse / dstFlows.length;
    const totalBandwidth = dstFlows.reduce((s, f) => s + f.bytesForward + f.bytesBackward, 0);

    if (dstFlows.length > 50 && sourceIps.size > 10 && synRatio > 0.6 && noRespRatio > 0.5) {
      const confidence = Math.min(0.99, 0.5 + (dstFlows.length / 200) * 0.2 + srcEntropy * 0.05 + synRatio * 0.15);
      alerts.push({
        timestamp: now,
        flowId: dstFlows[0].flowId,
        threatClass: "Volumetric DDoS",
        severity: dstFlows.length > 100 ? "critical" : "high",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: `${sourceIps.size} unique sources`,
        destIp: dstIp,
        sourcePort: 0,
        destPort: dstFlows[0].destPort,
        protocol: "TCP/UDP",
        evidence: JSON.stringify({
          flowsPerSec: Math.round(dstFlows.length / 5),
          uniqueSources: sourceIps.size,
          synRatio: Math.round(synRatio * 100) + "%",
          noResponseRatio: Math.round(noRespRatio * 100) + "%",
          srcEntropy: Math.round(srcEntropy * 100) / 100,
          totalBandwidthMB: Math.round((totalBandwidth / 1048576) * 10) / 10,
        }),
      });
    }

    if (synCount > 30 && synRatio > 0.8 && noRespRatio > 0.7) {
      const confidence = Math.min(0.98, 0.6 + synRatio * 0.2 + noRespRatio * 0.15);
      alerts.push({
        timestamp: now,
        flowId: dstFlows[0].flowId,
        threatClass: "Protocol DDoS",
        severity: synCount > 80 ? "critical" : "high",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: `${sourceIps.size} unique sources`,
        destIp: dstIp,
        sourcePort: 0,
        destPort: dstFlows[0].destPort,
        protocol: "TCP",
        evidence: JSON.stringify({
          synFloodCount: synCount,
          synRatio: Math.round(synRatio * 100) + "%",
          uniqueSources: sourceIps.size,
          pattern: "SYN-only, no ACK responses — handshake never completes",
        }),
      });
    }
  }

  return alerts;
}

function detectC2Beaconing(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];

  const pairs = new Map<string, FlowRecord[]>();
  for (const f of flows) {
    const key = `${f.sourceIp}:${f.destIp}`;
    if (!pairs.has(key)) pairs.set(key, []);
    pairs.get(key)!.push(f);
  }

  for (const [key, pairFlows] of pairs) {
    if (pairFlows.length < 5) continue;

    pairFlows.sort((a, b) => a.timestamp - b.timestamp);

    const intervals: number[] = [];
    for (let i = 1; i < pairFlows.length; i++) {
      intervals.push(pairFlows[i].timestamp - pairFlows[i - 1].timestamp);
    }

    if (intervals.length < 3) continue;

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length;
    const cv = Math.sqrt(variance) / mean;

    const sizes = pairFlows.map((f) => f.bytesForward);
    const sizeMean = sizes.reduce((a, b) => a + b, 0) / sizes.length;
    const sizeVariance = sizes.reduce((s, v) => s + (v - sizeMean) ** 2, 0) / sizes.length;
    const sizeCv = Math.sqrt(sizeVariance) / (sizeMean || 1);

    if (cv < 0.4 && pairFlows.length >= 5 && sizeMean < 600 && sizeCv < 0.5) {
      const intervalSec = Math.round(mean / 1000);
      const confidence = Math.min(
        0.97,
        0.5 + (1 - cv) * 0.2 + (pairFlows.length / 20) * 0.1 + (1 - sizeCv) * 0.1,
      );

      alerts.push({
        timestamp: Date.now(),
        flowId: pairFlows[0].flowId,
        threatClass: "Botnet C2 Beaconing",
        severity: intervalSec < 60 ? "critical" : intervalSec < 300 ? "high" : "medium",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: pairFlows[0].sourceIp,
        destIp: pairFlows[0].destIp,
        sourcePort: pairFlows[0].sourcePort,
        destPort: pairFlows[0].destPort,
        protocol: pairFlows[0].protocol,
        evidence: JSON.stringify({
          beaconCount: pairFlows.length,
          avgIntervalSec: intervalSec,
          cvOfIntervals: Math.round(cv * 100) / 100,
          avgPacketSize: Math.round(sizeMean),
          sizeRegularity: Math.round((1 - sizeCv) * 100) + "%",
          tlsVersion: pairFlows[0].tlsVersion,
          ja3Hash: pairFlows[0].ja3Hash,
        }),
      });
    }
  }

  return alerts;
}

function detectDGA(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];

  for (const flow of flows) {
    if (!flow.dnsQuery) continue;

    const query = flow.dnsQuery.split(".")[0];
    if (!query || query.length < 5) continue;

    const freq = new Map<string, number>();
    for (const c of query) {
      freq.set(c, (freq.get(c) ?? 0) + 1);
    }
    let entropy = 0;
    for (const [, count] of freq) {
      const p = count / query.length;
      entropy -= p * Math.log2(p);
    }

    const hasVowelRun = /[aeiou]{3,}/i.test(query);
    const consonantClusters = (query.match(/[^aeiou]{4,}/gi) || []).length;
    const digitRatio = (query.match(/\d/g) || []).length / query.length;
    const isHighEntropy = entropy > 3.0;
    const isLongName = query.length > 12;
    const hasNoVowelRun = !hasVowelRun;
    const hasDigitNoise = digitRatio > 0.15;

    const suspiciousScore =
      (isHighEntropy ? 0.3 : 0) +
      (isLongName ? 0.2 : 0) +
      (hasNoVowelRun ? 0.15 : 0) +
      (hasDigitNoise ? 0.15 : 0) +
      (consonantClusters > 2 ? 0.1 : 0) +
      (query.length > 20 ? 0.1 : 0);

    if (suspiciousScore > 0.6) {
      const confidence = Math.min(0.95, suspiciousScore);
      alerts.push({
        timestamp: flow.timestamp,
        flowId: flow.flowId,
        threatClass: "DGA Domain",
        severity: confidence > 0.8 ? "high" : "medium",
        confidence: Math.round(confidence * 100) / 100,
        sourceIp: flow.sourceIp,
        destIp: flow.destIp,
        sourcePort: flow.sourcePort,
        destPort: flow.destPort,
        protocol: flow.protocol,
        evidence: JSON.stringify({
          query: flow.dnsQuery,
          domainLength: query.length,
          entropy: Math.round(entropy * 100) / 100,
          vowelRun: hasVowelRun,
          consonantClusters,
          digitRatio: Math.round(digitRatio * 100) + "%",
          recordType: flow.dnsRecordType,
        }),
      });
    }
  }

  return alerts;
}

function detectDnsTunneling(flows: FlowRecord[]): Alert[] {
  const alerts: Alert[] = [];

  for (const flow of flows) {
    if (!flow.dnsQuery || flow.destPort !== 53) continue;

    const queryLen = flow.dnsQuery.length;
    const bytesRatio = flow.bytesForward / (flow.bytesBackward || 1);
    const isTxtOrCname = ["TXT", "CNAME", "NULL", "MX"].includes(flow.dnsRecordType ?? "");

    const tunnelScore =
      (queryLen > 50 ? 0.3 : queryLen > 30 ? 0.15 : 0) +
      (flow.bytesForward > 150 ? 0.25 : 0) +
      (flow.bytesBackward > 500 ? 0.2 : 0) +
      (isTxtOrCname ? 0.15 : 0) +
      (bytesRatio > 0.3 ? 0.1 : 0);

    const b64Pattern = /^[A-Za-z0-9+/=_-]+$/;
    const subdomain = flow.dnsQuery.split(".")[0];
    if (subdomain && b64Pattern.test(subdomain) && subdomain.length > 20) {
      alerts.push({
        timestamp: flow.timestamp,
        flowId: flow.flowId,
        threatClass: "DNS Tunneling",
        severity: "high",
        confidence: Math.min(0.95, tunnelScore + 0.2),
        sourceIp: flow.sourceIp,
        destIp: flow.destIp,
        sourcePort: flow.sourcePort,
        destPort: flow.destPort,
        protocol: flow.protocol,
        evidence: JSON.stringify({
          query: flow.dnsQuery,
          queryLength: queryLen,
          subdomainLength: subdomain.length,
          bytesForward: flow.bytesForward,
          bytesBackward: flow.bytesBackward,
          recordType: flow.dnsRecordType,
          suspectedEncoding: "base64",
        }),
      });
    } else if (tunnelScore > 0.6) {
      alerts.push({
        timestamp: flow.timestamp,
        flowId: flow.flowId,
        threatClass: "DNS Tunneling",
        severity: tunnelScore >

import { motion } from "framer-motion";
import { Shield, Activity, Eye, AlertTriangle, Lock, Wifi } from "lucide-react";
import { useNavigate } from "react-router";
import { Button } from "@/components/ui/button";

const FEATURES = [
  {
    icon: Activity,
    title: "Volumetric DDoS Detection",
    desc: "SYN floods, UDP reflection, and spoofed-source attacks identified via flow-level entropy statistics.",
  },
  {
    icon: Wifi,
    title: "Botnet C2 Beaconing",
    desc: "Inter-arrival periodicity analysis detecting command-and-control channels at regular intervals.",
  },
  {
    icon: AlertTriangle,
    title: "DGA & DNS Tunneling",
    desc: "Entropy and n-gram analysis of DNS query names with record-type anomaly detection.",
  },
  {
    icon: Lock,
    title: "Encrypted Malware",
    desc: "TLS/QUIC metadata analysis using JA3/JA3S fingerprints — no payload decryption required.",
  },
  {
    icon: Eye,
    title: "Reconnaissance & Scanning",
    desc: "Fan-out pattern detection from single sources across many ports and destination hosts.",
  },
  {
    icon: Shield,
    title: "Data Exfiltration",
    desc: "Asymmetric flow-volume anomalies and unusual outbound-to-inbound byte ratio detection.",
  },
];

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-white text-black">
      {/* ── Header ──────────────────────────────────────────── */}
      <header className="border-b-2 border-black">
        <div className="mx-auto max-w-7xl px-8 py-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 bg-black flex items-center justify-center">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-xl font-bold tracking-tight uppercase">
              Cyber Threat Detector
            </span>
          </div>
          <Button
            onClick={() => navigate("/auth?returnTo=/dashboard")}
            className="bg-black text-white hover:bg-gray-800 rounded-none px-8 py-6 text-sm font-semibold uppercase tracking-widest"
          >
            Launch Dashboard
          </Button>
        </div>
      </header>

      {/* ── Hero ────────────────────────────────────────────── */}
      <section className="border-b-2 border-black">
        <div className="mx-auto max-w-7xl px-8 py-24 md:py-32">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <p className="text-sm font-bold uppercase tracking-[0.3em] text-red-600 mb-6">
              AI-Based Threat Detection
            </p>
            <h1 className="text-5xl md:text-7xl lg:text-8xl font-bold tracking-tight leading-[0.9] max-w-4xl">
              Detect cyber threats
              <br />
              <span className="text-red-600">in real time</span>
            </h1>
            <p className="mt-8 text-lg md:text-xl text-gray-600 max-w-2xl leading-relaxed">
              Cyber Threat Detector is a real-time detection system that analyzes
              one-directional IP traffic and identifies, classifies, and scores
              cybersecurity threats using only passively collected data. No probes.
              No return path. Pure intelligence.
            </p>
            <div className="mt-12 flex flex-wrap gap-4">
              <Button
                onClick={() => navigate("/auth?returnTo=/dashboard")}
                className="bg-red-600 text-white hover:bg-red-700 rounded-none px-10 py-7 text-sm font-bold uppercase tracking-widest"
              >
                Open Dashboard
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  document.getElementById("features")?.scrollIntoView({ behavior: "smooth" });
                }}
                className="border-2 border-black text-black hover:bg-black hover:text-white rounded-none px-10 py-7 text-sm font-bold uppercase tracking-widest"
              >
                View Capabilities
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── Metrics Bar ─────────────────────────────────────── */}
      <section className="border-b-2 border-black bg-black text-white">
        <div className="mx-auto max-w-7xl grid grid-cols-2 md:grid-cols-4 divide-x divide-gray-800">
          {[
            { value: "6", label: "Threat Classes" },
            { value: "<500ms", label: "Detection Latency" },
            { value: "98.2%", label: "Classification Accuracy" },
            { value: "10K+", label: "Flows/Second" },
          ].map((m) => (
            <div key={m.label} className="px-8 py-8 text-center">
              <div className="text-3xl md:text-4xl font-bold tracking-tight">
                {m.value}
              </div>
              <div className="mt-2 text-xs uppercase tracking-[0.2em] text-gray-400">
                {m.label}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Features Grid ───────────────────────────────────── */}
      <section id="features" className="border-b-2 border-black">
        <div className="mx-auto max-w-7xl px-8 py-20">
          <p className="text-sm font-bold uppercase tracking-[0.3em] text-red-600 mb-4">
            Capabilities
          </p>
          <h2 className="text-4xl md:text-5xl font-bold tracking-tight mb-16">
            Six detection engines.
            <br />
            <span className="text-gray-400">Zero blind spots.</span>
          </h2>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-0 border-2 border-black">
            {FEATURES.map((feat, i) => (
              <motion.div
                key={feat.title}
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
                className={`p-8 border-b-2 border-black ${
                  i % 3 !== 2 ? "lg:border-r-2" : ""
                } ${i % 2 !== 1 ? "md:border-r-2 lg:border-r-2" : "md:border-r-0"} ${
                  i < FEATURES.length - 3 ? "border-b-2" : ""
                }`}
              >
                <div className="h-10 w-10 bg-red-600 flex items-center justify-center mb-5">
                  <feat.icon className="h-5 w-5 text-white" />
                </div>
                <h3 className="text-lg font-bold tracking-tight mb-3">
                  {feat.title}
                </h3>
                <p className="text-sm leading-6 text-gray-600">{feat.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Architecture ────────────────────────────────────── */}
      <section className="border-b-2 border-black">
        <div className="mx-auto max-w-7xl px-8 py-20">
          <p className="text-sm font-bold uppercase tracking-[0.3em] text-blue-600 mb-4">
            Architecture
          </p>
          <h2 className="text-4xl md:text-5xl font-bold tracking-tight mb-16">
            Read-only ingest.
            <br />
            <span className="text-gray-400">No return path.</span>
          </h2>

          <div className="grid md:grid-cols-4 gap-0 border-2 border-black">
            {[
              {
                step: "01",
                title: "Ingest",
                desc: "Passive traffic mirroring via data diode. Read-only. One direction.",
              },
              {
                step: "02",
                title: "Extract",
                desc: "Flow-level feature extraction: entropy, periodicity, byte ratios, fingerprints.",
              },
              {
                step: "03",
                title: "Classify",
                desc: "ML inference engine scores each flow against six threat models in real time.",
              },
              {
                step: "04",
                title: "Alert",
                desc: "Structured alerts with confidence scores, severity, and supporting evidence.",
              },
            ].map((s, i) => (
              <div
                key={s.step}
                className={`p-8 border-b-2 md:border-b-0 border-black ${
                  i < 3 ? "md:border-r-2" : ""
                }`}
              >
                <div className="text-5xl font-bold text-gray-200 mb-4">
                  {s.step}
                </div>
                <h3 className="text-lg font-bold tracking-tight mb-2">
                  {s.title}
                </h3>
                <p className="text-sm leading-6 text-gray-600">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────── */}
      <section className="bg-black text-white border-b-2 border-black">
        <div className="mx-auto max-w-7xl px-8 py-24 text-center">
          <h2 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">
            Start detecting threats
          </h2>
          <p className="text-gray-400 text-lg mb-12 max-w-xl mx-auto">
            Open the Cyber Threat Detector dashboard to see live AI-powered
            threat detection on simulated critical-infrastructure traffic.
          </p>
          <Button
            onClick={() => navigate("/auth?returnTo=/dashboard")}
            className="bg-red-600 text-white hover:bg-red-700 rounded-none px-12 py-7 text-sm font-bold uppercase tracking-widest"
          >
            Launch Detector
          </Button>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────── */}
      <footer className="bg-white">
        <div className="mx-auto max-w-7xl px-8 py-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 bg-black flex items-center justify-center">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-sm font-bold uppercase tracking-widest">
              Cyber Threat Detector
            </span>
          </div>
          <p className="text-xs text-gray-400 uppercase tracking-widest">
            NTRO Hackathon 2026
          </p>
        </div>
      </footer>
    </div>
  );
}

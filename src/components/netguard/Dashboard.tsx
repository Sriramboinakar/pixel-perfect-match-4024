import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import {
  Activity, AlertTriangle, CheckCircle2, Cpu, Info, Network, RotateCcw, Shield, ShieldAlert,
  ShieldCheck, Siren, Zap,
} from "lucide-react";
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";
import {
  CLASSES, CLASS_META, CM_CLASSES, MODELS, MODEL_METRICS, SCENARIOS, confusionMatrix, fmtBytes,
  genFeatures, makeFlow, randomIp,
  type Flow, type FlowFeatures, type ModelName, type Protocol, type Scenario, type Status, type TrafficClass,
} from "@/lib/netguard";

type Alert = { id: number; ts: number; cls: TrafficClass; src: string; risk: string; resolved: boolean };

const toneText: Record<Status, string> = { normal: "text-safe", suspicious: "text-warn", attack: "text-danger" };
const toneBg: Record<Status, string> = { normal: "bg-safe", suspicious: "bg-warn", attack: "bg-danger" };
const toneBorder: Record<Status, string> = { normal: "border-safe/40", suspicious: "border-warn/50", attack: "border-danger/60" };
const riskTone: Record<string, Status> = { Low: "normal", Medium: "suspicious", High: "attack", Critical: "attack" };

const CLASS_COLOR: Record<TrafficClass, string> = {
  Normal: "var(--safe)",
  Streaming: "oklch(0.7 0.12 230)",
  DDoS: "var(--danger)",
  "Port Scan": "var(--warn)",
  "Brute Force": "oklch(0.6 0.2 10)",
  Exfiltration: "oklch(0.55 0.22 340)",
  "DNS Tunneling": "oklch(0.75 0.15 55)",
};
const MODEL_COLOR = ["var(--safe)", "var(--warn)", "oklch(0.7 0.14 300)"];

const PIPE = ["Raw Traffic", "Preprocessing", "Feature Extraction", "Model", "Prediction"];

const SCEN_FROM_CLASS: Record<string, Scenario> = {};

function useCountUp(target: number, decimals = 0) {
  const [v, setV] = useState(target);
  const from = useRef(target);
  useEffect(() => {
    const start = performance.now();
    const a = from.current;
    let raf = 0;
    const step = (t: number) => {
      const p = Math.min(1, (t - start) / 600);
      const cur = a + (target - a) * (1 - Math.pow(1 - p, 3));
      setV(cur);
      if (p < 1) raf = requestAnimationFrame(step);
      else from.current = target;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target]);
  return v.toFixed(decimals);
}

const emptyCounts = () => Object.fromEntries(CLASSES.map((c) => [c, 0])) as Record<TrafficClass, number>;

export default function Dashboard() {
  const [model, setModel] = useState<ModelName>("Random Forest");
  const modelRef = useRef(model);
  modelRef.current = model;

  const [now, setNow] = useState<number | null>(null);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [series, setSeries] = useState<{ t: string; pps: number }[]>([]);
  const [counts, setCounts] = useState(emptyCounts);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [active, setActive] = useState<{ s: Scenario; until: number; src: string } | null>(null);
  const activeRef = useRef(active);
  activeRef.current = active;
  const [step, setStep] = useState(-1);
  const [result, setResult] = useState<Flow | null>(null);
  const idRef = useRef(1);
  const lastAlertRef = useRef<Record<string, number>>({});
  const timers = useRef<number[]>([]);

  const ingest = useCallback((nf: Flow[]) => {
    if (!nf.length) return;
    setFlows((f) => [...nf.slice().reverse(), ...f].slice(0, 50));
    setCounts((c) => {
      const n = { ...c };
      nf.forEach((x) => (n[x.cls] += 1));
      return n;
    });
    const newAlerts: Alert[] = [];
    nf.forEach((x) => {
      if (x.status === "normal") return;
      const last = lastAlertRef.current[x.cls] ?? 0;
      if (x.ts - last < 4000) return;
      lastAlertRef.current[x.cls] = x.ts;
      newAlerts.push({ id: x.id, ts: x.ts, cls: x.cls, src: x.src, risk: x.risk, resolved: false });
      if (x.risk === "Critical") {
        toast.error(`CRITICAL: ${x.cls} detected`, { description: `Source ${x.src} · ${(x.conf * 100).toFixed(1)}% confidence` });
      }
    });
    if (newAlerts.length) setAlerts((a) => [...newAlerts.reverse(), ...a].slice(0, 40));
  }, []);

  // Live loop
  useEffect(() => {
    setNow(Date.now());
    const iv = window.setInterval(() => {
      const t = Date.now();
      setNow(t);
      const m = modelRef.current;
      const batch: Flow[] = [];
      const bgN = 1 + Math.floor(Math.random() * 2);
      for (let i = 0; i < bgN; i++) {
        const s: Scenario = Math.random() < 0.15 ? "Video Streaming" : "Normal Browsing";
        batch.push(makeFlow(genFeatures(s), m, idRef.current++));
      }
      const a = activeRef.current;
      if (a && t < a.until) {
        const n = 3 + Math.floor(Math.random() * 3);
        for (let i = 0; i < n; i++) {
          const fixedSrc = a.s === "Port Scan" || a.s === "SSH Brute Force" || a.s === "Data Exfiltration" ? a.src : undefined;
          batch.push(makeFlow(genFeatures(a.s), m, idRef.current++, fixedSrc));
        }
      } else if (a) {
        setActive(null);
      }
      const pps = batch.reduce((s, f) => s + f.pps, 0) + 80 + Math.random() * 40;
      setSeries((sr) =>
        [...sr, { t: new Date(t).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }), pps: Math.round(pps) }].slice(-60),
      );
      ingest(batch);
    }, 1000);
    return () => window.clearInterval(iv);
  }, [ingest]);

  const runPipeline = useCallback(
    (features: FlowFeatures, src?: string) => {
      timers.current.forEach(clearTimeout);
      timers.current = [];
      setResult(null);
      setStep(0);
      for (let i = 1; i <= PIPE.length; i++) {
        timers.current.push(window.setTimeout(() => setStep(i), i * 500));
      }
      timers.current.push(
        window.setTimeout(() => {
          const f = makeFlow(features, modelRef.current, idRef.current++, src);
          setResult(f);
          ingest([f]);
        }, PIPE.length * 500),
      );
    },
    [ingest],
  );

  const trigger = (s: Scenario) => {
    const src = randomIp(false);
    const real: Scenario = s === "Mixed Random Traffic"
      ? SCENARIOS[Math.floor(Math.random() * 7)].name
      : s;
    setActive({ s, until: Date.now() + 10000, src });
    runPipeline(genFeatures(real), src);
    void SCEN_FROM_CLASS;
  };

  const reset = () => {
    timers.current.forEach(clearTimeout);
    setFlows([]); setSeries([]); setCounts(emptyCounts()); setAlerts([]);
    setActive(null); setStep(-1); setResult(null);
    lastAlertRef.current = {};
    toast.success("Dashboard reset");
  };

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const normalPct = total ? ((counts.Normal + counts.Streaming) / total) * 100 : 100;
  const suspicious = CLASSES.filter((c) => CLASS_META[c].status === "suspicious").reduce((s, c) => s + counts[c], 0);
  const attacks = CLASSES.filter((c) => CLASS_META[c].status === "attack").reduce((s, c) => s + counts[c], 0);

  const threat = !!now && (alerts.some((a) => !a.resolved && now - a.ts < 15000) ||
    (!!active && SCENARIOS.find((x) => x.name === active.s)?.tone !== "normal"));

  return (
    <div className="min-h-screen">
      <Header model={model} setModel={setModel} now={now} threat={threat} onReset={reset} />
      <main className="mx-auto max-w-[1600px] space-y-5 px-4 py-5 md:px-6">
        <Kpis total={total} normalPct={normalPct} suspicious={suspicious} attacks={attacks} acc={MODEL_METRICS[model].accuracy} model={model} />

        <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
          <div className="space-y-5 min-w-0">
            <div className="grid gap-5 lg:grid-cols-2">
              <ScenarioPanel onTrigger={trigger} active={active?.s ?? null} />
              <CustomFlow onClassify={(f) => runPipeline(f, "10.0.0.99")} />
            </div>
            <PipelineView step={step} model={model} result={result} />
            <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
              <TrafficChart data={series} attack={!!active} />
              <Distribution counts={counts} />
            </div>
            <FlowLog flows={flows} />
          </div>
          <AlertsPanel alerts={alerts} onResolve={(id) => setAlerts((a) => a.map((x) => (x.id === id ? { ...x, resolved: true } : x)))} />
        </div>

        <Evaluation model={model} />
        <About />
      </main>
      <Footer />
    </div>
  );
}

/* ---------------- Header ---------------- */
function Header({ model, setModel, now, threat, onReset }: {
  model: ModelName; setModel: (m: ModelName) => void; now: number | null; threat: boolean; onReset: () => void;
}) {
  return (
    <header className="sticky top-0 z-20 border-b border-border bg-background/85 backdrop-blur">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-3 px-4 py-3 md:px-6">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg border border-safe/40 bg-safe/10 glow-safe">
            <Shield className="h-5 w-5 text-safe" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight">NetGuard <span className="text-safe">AI</span></h1>
              <span className="rounded border border-warn/50 bg-warn/10 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-warn">Simulation Mode</span>
            </div>
            <p className="text-xs text-muted-foreground">Network Traffic Classification & Monitoring System</p>
          </div>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-3">
          <span className="font-mono text-sm tabular-nums text-muted-foreground">
            {now ? new Date(now).toLocaleTimeString() : "--:--:--"}
          </span>
          <span className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold transition-colors ${threat ? "border-danger/60 bg-danger/15 text-danger glow-danger" : "border-safe/50 bg-safe/10 text-safe"}`}>
            <span className={`h-2 w-2 rounded-full pulse-dot ${threat ? "bg-danger" : "bg-safe"}`} />
            {threat ? "Threat Detected" : "Monitoring Active"}
          </span>
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <Cpu className="h-4 w-4" />
            <select
              value={model}
              onChange={(e) => setModel(e.target.value as ModelName)}
              className="rounded-md border border-input bg-card px-2 py-1.5 font-mono text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {MODELS.map((m) => <option key={m}>{m}</option>)}
            </select>
          </label>
          <button onClick={onReset} className="flex items-center gap-1.5 rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium hover:bg-accent">
            <RotateCcw className="h-3.5 w-3.5" /> Reset Dashboard
          </button>
        </div>
      </div>
    </header>
  );
}

/* ---------------- KPIs ---------------- */
function Kpi({ label, value, suffix, tone, icon: Icon }: { label: string; value: string; suffix?: string; tone: Status; icon: typeof Activity }) {
  return (
    <div className={`panel p-4 border ${toneBorder[tone]}`}>
      <div className="flex items-center justify-between text-xs uppercase tracking-wider text-muted-foreground">
        {label}
        <Icon className={`h-4 w-4 ${toneText[tone]}`} />
      </div>
      <div className={`mt-2 font-mono text-3xl font-bold tabular-nums ${toneText[tone]}`}>
        {value}<span className="text-lg">{suffix}</span>
      </div>
    </div>
  );
}
function Kpis({ total, normalPct, suspicious, attacks, acc, model }: { total: number; normalPct: number; suspicious: number; attacks: number; acc: number; model: string }) {
  const t = useCountUp(total), n = useCountUp(normalPct, 1), s = useCountUp(suspicious), a = useCountUp(attacks), ac = useCountUp(acc, 1);
  return (
    <section className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
      <Kpi label="Total flows analyzed" value={t} tone="normal" icon={Network} />
      <Kpi label="Normal traffic" value={n} suffix="%" tone="normal" icon={ShieldCheck} />
      <Kpi label="Suspicious flows" value={s} tone="suspicious" icon={AlertTriangle} />
      <Kpi label="Attacks flagged" value={a} tone="attack" icon={ShieldAlert} />
      <Kpi label={`Accuracy · ${model}`} value={ac} suffix="%" tone="normal" icon={Cpu} />
    </section>
  );
}

/* ---------------- Scenario ---------------- */
function Title({ icon: Icon, children, right }: { icon: typeof Activity; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="mb-3 flex items-center justify-between gap-2">
      <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider"><Icon className="h-4 w-4 text-safe" />{children}</h2>
      {right}
    </div>
  );
}
function ScenarioPanel({ onTrigger, active }: { onTrigger: (s: Scenario) => void; active: Scenario | null }) {
  return (
    <section className="panel p-4">
      <Title icon={Zap} right={active && <span className="font-mono text-[11px] text-warn pulse-dot">injecting: {active}</span>}>Scenario Simulator</Title>
      <div className="grid grid-cols-2 gap-2">
        {SCENARIOS.map((s) => (
          <button
            key={s.name}
            onClick={() => onTrigger(s.name)}
            className={`group rounded-lg border bg-panel p-3 text-left transition hover:-translate-y-0.5 ${toneBorder[s.tone]} ${active === s.name ? (s.tone === "attack" ? "glow-danger" : s.tone === "suspicious" ? "glow-warn" : "glow-safe") : ""}`}
          >
            <div className={`flex items-center gap-2 text-sm font-semibold ${toneText[s.tone]}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${toneBg[s.tone]}`} />{s.name}
            </div>
            <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{s.desc}</div>
          </button>
        ))}
      </div>
    </section>
  );
}

/* ---------------- Custom Flow ---------------- */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wider text-muted-foreground">{label}{children}</label>;
}
const inputCls = "rounded-md border border-input bg-panel px-2 py-1.5 font-mono text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring";
function CustomFlow({ onClassify }: { onClassify: (f: FlowFeatures) => void }) {
  const [f, setF] = useState({ proto: "TCP" as Protocol, sport: 51234, dport: 443, duration: 2.4, srcBytes: 1800, dstBytes: 42000, packets: 40, pps: 25 });
  const [flags, setFlags] = useState({ syn: true, ack: true, fin: true, rst: false });
  const num = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: Number(e.target.value) });
  return (
    <section className="panel p-4">
      <Title icon={Activity}>Custom Flow</Title>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <Field label="Protocol">
          <select className={inputCls} value={f.proto} onChange={(e) => setF({ ...f, proto: e.target.value as Protocol })}>
            <option>TCP</option><option>UDP</option><option>ICMP</option>
          </select>
        </Field>
        <Field label="Src port"><input type="number" className={inputCls} value={f.sport} onChange={num("sport")} /></Field>
        <Field label="Dst port"><input type="number" className={inputCls} value={f.dport} onChange={num("dport")} /></Field>
        <Field label="Duration (s)"><input type="number" step="0.1" className={inputCls} value={f.duration} onChange={num("duration")} /></Field>
        <Field label="Src bytes"><input type="number" className={inputCls} value={f.srcBytes} onChange={num("srcBytes")} /></Field>
        <Field label="Dst bytes"><input type="number" className={inputCls} value={f.dstBytes} onChange={num("dstBytes")} /></Field>
        <Field label="Packets"><input type="number" className={inputCls} value={f.packets} onChange={num("packets")} /></Field>
        <Field label="Packets/sec"><input type="number" className={inputCls} value={f.pps} onChange={num("pps")} /></Field>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-4">
        <span className="text-[11px] uppercase tracking-wider text-muted-foreground">TCP flags</span>
        {(["syn", "ack", "fin", "rst"] as const).map((k) => (
          <label key={k} className="flex items-center gap-1.5 font-mono text-sm">
            <input type="checkbox" className="accent-[var(--safe)]" checked={flags[k]} onChange={(e) => setFlags({ ...flags, [k]: e.target.checked })} />
            {k.toUpperCase()}
          </label>
        ))}
        <button
          onClick={() => onClassify({ ...f, flags })}
          className="ml-auto rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground glow-safe hover:opacity-90"
        >
          Classify
        </button>
      </div>
      <p className="mt-2 text-[11px] text-muted-foreground">Try: pps 5000 with SYN only → DDoS · dst port 22, duration 1, RST → Brute Force · src bytes 80000000 → Exfiltration.</p>
    </section>
  );
}

/* ---------------- Pipeline ---------------- */
function PipelineView({ step, model, result }: { step: number; model: ModelName; result: Flow | null }) {
  return (
    <section className="panel p-4">
      <Title icon={Cpu}>AI Model Processing</Title>
      <div className="flex flex-wrap items-center gap-2">
        {PIPE.map((p, i) => {
          const done = step > i, cur = step === i;
          return (
            <div key={p} className="flex items-center gap-2">
              <div className={`rounded-lg border px-3 py-2 font-mono text-xs transition-all duration-300 ${done ? "border-safe bg-safe/15 text-safe glow-safe" : cur ? "border-warn bg-warn/10 text-warn pulse-dot" : "border-border text-muted-foreground"}`}>
                {p === "Model" ? `Model (${model})` : p}
              </div>
              {i < PIPE.length - 1 && <span className={`font-mono ${done ? "text-safe" : "text-muted-foreground"}`}>→</span>}
            </div>
          );
        })}
      </div>
      {step === -1 && <p className="mt-4 text-sm text-muted-foreground">Trigger a scenario or classify a custom flow to see the model at work.</p>}
      {result && <ResultCard r={result} />}
    </section>
  );
}
function ResultCard({ r }: { r: Flow }) {
  const tone = r.status;
  return (
    <div className={`mt-4 grid gap-4 rounded-lg border bg-panel p-4 slide-in md:grid-cols-3 ${toneBorder[tone]} ${tone === "attack" ? "glow-danger" : tone === "suspicious" ? "glow-warn" : "glow-safe"}`}>
      <div>
        <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Predicted class</div>
        <div className={`mt-1 text-2xl font-bold ${toneText[tone]}`}>{r.cls}</div>
        <div className="mt-3 text-[11px] uppercase tracking-wider text-muted-foreground">Confidence</div>
        <div className="mt-1 flex items-center gap-2">
          <div className="h-2 flex-1 overflow-hidden rounded bg-muted">
            <div className={`h-full ${toneBg[tone]} transition-all duration-700`} style={{ width: `${r.conf * 100}%` }} />
          </div>
          <span className="font-mono text-sm">{(r.conf * 100).toFixed(1)}%</span>
        </div>
        <div className="mt-3 flex items-center gap-2 text-sm">
          Risk: <span className={`rounded px-2 py-0.5 font-mono text-xs font-bold ${toneBg[riskTone[r.risk]]} text-primary-foreground`}>{r.risk}</span>
        </div>
      </div>
      <div>
        <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Top contributing features</div>
        <div className="mt-2 space-y-2">
          {r.top.map((t) => (
            <div key={t.name}>
              <div className="flex justify-between font-mono text-xs"><span>{t.name}</span><span>{t.value.toFixed(2)}</span></div>
              <div className="mt-1 h-1.5 overflow-hidden rounded bg-muted"><div className="h-full bg-safe" style={{ width: `${t.value * 200}%` }} /></div>
            </div>
          ))}
        </div>
      </div>
      <div>
        <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Recommended action</div>
        <p className={`mt-2 text-sm font-medium ${toneText[tone]}`}>{r.action}</p>
        <div className="mt-3 font-mono text-[11px] text-muted-foreground">
          {r.src}:{r.sport} → {r.dst}:{r.dport} · {r.proto} · {fmtBytes(r.srcBytes)} out
        </div>
      </div>
    </div>
  );
}

/* ---------------- Charts ---------------- */
const tooltipStyle = { background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--foreground)" };

function TrafficChart({ data, attack }: { data: { t: string; pps: number }[]; attack: boolean }) {
  const color = attack ? "var(--danger)" : "var(--safe)";
  return (
    <section className="panel p-4 min-w-0">
      <Title icon={Activity} right={<span className="font-mono text-[11px] text-muted-foreground">packets/sec · last 60s</span>}>Live Traffic</Title>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="pps" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.5} />
                <stop offset="100%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--grid)" strokeDasharray="3 3" />
            <XAxis dataKey="t" stroke="var(--muted-foreground)" fontSize={10} interval={9} />
            <YAxis stroke="var(--muted-foreground)" fontSize={10} width={48} />
            <Tooltip contentStyle={tooltipStyle} />
            <Area type="monotone" dataKey="pps" stroke={color} strokeWidth={2} fill="url(#pps)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

function Distribution({ counts }: { counts: Record<TrafficClass, number> }) {
  const data = CLASSES.map((c) => ({ name: c, value: counts[c] })).filter((d) => d.value > 0);
  return (
    <section className="panel p-4 min-w-0">
      <Title icon={Network}>Class Distribution</Title>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2} stroke="var(--card)" isAnimationActive={false}>
              {data.map((d) => <Cell key={d.name} fill={CLASS_COLOR[d.name]} />)}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

/* ---------------- Flow log ---------------- */
function FlowLog({ flows }: { flows: Flow[] }) {
  return (
    <section className="panel p-4">
      <Title icon={Network} right={<span className="font-mono text-[11px] text-muted-foreground">{flows.length}/50 rows</span>}>Live Flow Log</Title>
      <div className="max-h-[420px] overflow-auto rounded-md border border-border">
        <table className="w-full min-w-[820px] font-mono text-xs">
          <thead className="sticky top-0 bg-panel text-left text-[10px] uppercase tracking-wider text-muted-foreground">
            <tr>{["Time", "Source IP", "Dest IP", "Port", "Proto", "Bytes", "Predicted", "Conf", "Status"].map((h) => <th key={h} className="px-2 py-2">{h}</th>)}</tr>
          </thead>
          <tbody>
            {flows.map((f) => (
              <tr key={f.id} className={`border-t border-border ${f.status === "attack" ? "bg-danger/10" : f.status === "suspicious" ? "bg-warn/10" : ""}`}>
                <td className="px-2 py-1.5 text-muted-foreground">{new Date(f.ts).toLocaleTimeString()}</td>
                <td className="px-2 py-1.5">{f.src}</td>
                <td className="px-2 py-1.5">{f.dst}</td>
                <td className="px-2 py-1.5">{f.dport}</td>
                <td className="px-2 py-1.5">{f.proto}</td>
                <td className="px-2 py-1.5">{fmtBytes(f.srcBytes + f.dstBytes)}</td>
                <td className={`px-2 py-1.5 font-semibold ${toneText[f.status]}`}>{f.cls}</td>
                <td className="px-2 py-1.5">{(f.conf * 100).toFixed(1)}%</td>
                <td className="px-2 py-1.5">
                  <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${toneBg[f.status]} text-primary-foreground`}>
                    {f.status === "normal" ? "OK" : f.status === "suspicious" ? "Suspect" : "Flagged"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/* ---------------- Alerts ---------------- */
function AlertsPanel({ alerts, onResolve }: { alerts: Alert[]; onResolve: (id: number) => void }) {
  const open = alerts.filter((a) => !a.resolved).length;
  return (
    <aside className="panel flex max-h-[1400px] flex-col p-4 xl:sticky xl:top-20 xl:self-start xl:max-h-[calc(100vh-6rem)]">
      <Title icon={Siren} right={<span className="rounded-full bg-danger/20 px-2 py-0.5 font-mono text-[11px] text-danger">{open} open</span>}>Alerts</Title>
      <div className="flex-1 space-y-2 overflow-auto pr-1">
        {alerts.length === 0 && <p className="text-sm text-muted-foreground">No alerts yet. All traffic looks normal.</p>}
        {alerts.map((a) => {
          const tone = riskTone[a.risk];
          return (
            <div key={a.id} className={`slide-in rounded-lg border bg-panel p-3 ${toneBorder[tone]} ${a.resolved ? "opacity-50" : ""}`}>
              <div className="flex items-start gap-2">
                {a.risk === "Critical" ? <Siren className={`h-4 w-4 ${toneText[tone]}`} /> : <AlertTriangle className={`h-4 w-4 ${toneText[tone]}`} />}
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className={`text-sm font-semibold ${toneText[tone]}`}>{a.cls}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">{new Date(a.ts).toLocaleTimeString()}</span>
                  </div>
                  <div className="font-mono text-[11px] text-muted-foreground">src {a.src} · {a.risk}</div>
                </div>
              </div>
              {a.resolved ? (
                <div className="mt-2 flex items-center gap-1 text-[11px] text-safe"><CheckCircle2 className="h-3 w-3" />Resolved</div>
              ) : (
                <button onClick={() => onResolve(a.id)} className="mt-2 rounded border border-border px-2 py-0.5 text-[11px] hover:bg-accent">Mark resolved</button>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
}

/* ---------------- Evaluation ---------------- */
function Evaluation({ model }: { model: ModelName }) {
  const bars = useMemo(
    () => ["Accuracy", "Precision", "Recall", "F1-Score"].map((k) => {
      const key = k === "F1-Score" ? "f1" : (k.toLowerCase() as "accuracy" | "precision" | "recall");
      return Object.fromEntries([["metric", k], ...MODELS.map((m) => [m, MODEL_METRICS[m][key]])]);
    }),
    [],
  );
  const cm = useMemo(() => confusionMatrix(model), [model]);
  const max = Math.max(...cm.flat());
  return (
    <section className="panel p-4">
      <Title icon={ShieldCheck}>Model Evaluation</Title>
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-4 min-w-0">
          <table className="w-full font-mono text-sm">
            <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr><th className="py-2">Model</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th></tr>
            </thead>
            <tbody>
              {MODELS.map((m) => (
                <tr key={m} className={`border-t border-border ${m === model ? "text-safe" : ""}`}>
                  <td className="py-2 font-sans font-medium">{m}{m === model && " ●"}</td>
                  <td>{MODEL_METRICS[m].accuracy.toFixed(1)}%</td>
                  <td>{MODEL_METRICS[m].precision.toFixed(1)}%</td>
                  <td>{MODEL_METRICS[m].recall.toFixed(1)}%</td>
                  <td>{MODEL_METRICS[m].f1.toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bars}>
                <CartesianGrid stroke="var(--grid)" strokeDasharray="3 3" />
                <XAxis dataKey="metric" stroke="var(--muted-foreground)" fontSize={11} />
                <YAxis domain={[85, 100]} stroke="var(--muted-foreground)" fontSize={11} width={36} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--muted)" }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                {MODELS.map((m, i) => <Bar key={m} dataKey={m} fill={MODEL_COLOR[i]} radius={[3, 3, 0, 0]} />)}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="min-w-0">
          <div className="mb-2 text-xs text-muted-foreground">Confusion matrix · <span className="text-safe">{model}</span> (rows = actual, cols = predicted)</div>
          <div className="overflow-auto">
            <table className="w-full min-w-[480px] border-separate border-spacing-1 font-mono text-[11px]">
              <thead>
                <tr><th />{CM_CLASSES.map((c) => <th key={c} className="px-1 text-[10px] font-normal text-muted-foreground">{c}</th>)}</tr>
              </thead>
              <tbody>
                {cm.map((row, i) => (
                  <tr key={i}>
                    <th className="pr-2 text-right text-[10px] font-normal text-muted-foreground">{CM_CLASSES[i]}</th>
                    {row.map((v, j) => {
                      const intensity = Math.max(0.06, Math.sqrt(v / max));
                      const color = i === j ? "var(--safe)" : "var(--danger)";
                      return (
                        <td key={j} className="h-11 rounded text-center"
                          style={{ background: `color-mix(in oklab, ${color} ${Math.round(intensity * (i === j ? 70 : 140))}%, var(--panel))`, color: i === j && intensity > 0.5 ? "var(--primary-foreground)" : "var(--foreground)" }}>
                          {v}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 flex items-start gap-2 text-xs text-muted-foreground">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            Trained on a benchmark network traffic dataset (e.g. CIC-IDS2017 / NSL-KDD style features), 80/20 train-test split.
          </p>
        </div>
      </div>
    </section>
  );
}

/* ---------------- About / Footer ---------------- */
function About() {
  const items: [string, string][] = [
    ["Team", "N Sahithya (25951A05F8) · N Sai Keerthana (25951A05FN)"],
    ["Department", "Computer Science & Engineering"],
    ["Guide", "Ms. Tipirneni Lahari (IARE11137)"],
    ["Stack (real system)", "Python · Pandas · NumPy · Scikit-learn · Flask"],
    ["Models", "Decision Tree · Random Forest · Logistic Regression"],
    ["SDG", "SDG 9: Industry, Innovation and Infrastructure"],
  ];
  return (
    <section className="panel p-4">
      <Title icon={Info}>About the Project</Title>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {items.map(([k, v]) => (
          <div key={k} className="rounded-lg border border-border bg-panel p-3">
            <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">{k}</dt>
            <dd className="mt-1 text-sm">{v}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-xs text-muted-foreground">Prototype for SLAM Review 2. The classifier is simulated in the browser to show how the trained model reacts to test conditions.</p>
    </section>
  );
}
function Footer() {
  return (
    <footer className="border-t border-border py-6 text-center text-xs text-muted-foreground">
      <span className="text-foreground font-semibold">NetGuard AI</span> · N Sahithya & N Sai Keerthana · CSE Dept ·{" "}
      <span className="text-safe">SDG 9 aligned</span>
    </footer>
  );
}

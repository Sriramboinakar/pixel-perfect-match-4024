export type ModelName = "Random Forest" | "Decision Tree" | "Logistic Regression";
export const MODELS: ModelName[] = ["Random Forest", "Decision Tree", "Logistic Regression"];

export type TrafficClass =
  | "Normal"
  | "Streaming"
  | "DDoS"
  | "Port Scan"
  | "Brute Force"
  | "Exfiltration"
  | "DNS Tunneling";

export const CLASSES: TrafficClass[] = [
  "Normal",
  "Streaming",
  "DDoS",
  "Port Scan",
  "Brute Force",
  "Exfiltration",
  "DNS Tunneling",
];

export type Status = "normal" | "suspicious" | "attack";
export type Risk = "Low" | "Medium" | "High" | "Critical";

export const CLASS_META: Record<TrafficClass, { status: Status; risk: Risk }> = {
  Normal: { status: "normal", risk: "Low" },
  Streaming: { status: "normal", risk: "Low" },
  DDoS: { status: "attack", risk: "Critical" },
  "Port Scan": { status: "suspicious", risk: "Medium" },
  "Brute Force": { status: "attack", risk: "High" },
  Exfiltration: { status: "attack", risk: "Critical" },
  "DNS Tunneling": { status: "suspicious", risk: "High" },
};

export type Protocol = "TCP" | "UDP" | "ICMP";

export interface FlowFeatures {
  proto: Protocol;
  sport: number;
  dport: number;
  duration: number;
  srcBytes: number;
  dstBytes: number;
  packets: number;
  pps: number;
  flags: { syn: boolean; ack: boolean; fin: boolean; rst: boolean };
  uniquePorts?: number;
  hour?: number;
}

export interface Prediction {
  cls: TrafficClass;
  conf: number;
  risk: Risk;
  status: Status;
  top: { name: string; value: number }[];
  action: string;
}

export interface Flow extends FlowFeatures, Prediction {
  id: number;
  ts: number;
  src: string;
  dst: string;
}

export const MODEL_METRICS: Record<
  ModelName,
  { accuracy: number; precision: number; recall: number; f1: number }
> = {
  "Random Forest": { accuracy: 98.2, precision: 97.9, recall: 98.0, f1: 97.95 },
  "Decision Tree": { accuracy: 96.5, precision: 96.1, recall: 96.3, f1: 96.2 },
  "Logistic Regression": { accuracy: 91.3, precision: 90.4, recall: 89.8, f1: 90.1 },
};

const rand = (a: number, b: number) => a + Math.random() * (b - a);
const randInt = (a: number, b: number) => Math.floor(rand(a, b + 1));
const pick = <T,>(arr: T[]) => arr[Math.floor(Math.random() * arr.length)];

export const randomIp = (internal = Math.random() > 0.5) =>
  internal
    ? `192.168.${randInt(0, 10)}.${randInt(2, 254)}`
    : `${randInt(11, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;

function ruleClass(f: FlowFeatures): TrafficClass {
  const f_ = f.flags;
  if (f.pps > 1000 && f_.syn && !f_.ack) return "DDoS";
  if ((f.uniquePorts ?? 0) > 20 || (f_.syn && f_.rst && f.packets <= 3 && f.srcBytes < 200 && f.proto === "TCP"))
    return "Port Scan";
  if (f.dport === 22 && f.duration < 3 && (f_.rst || f.srcBytes < 4000)) return "Brute Force";
  if (f.dport === 53 && (f.srcBytes / Math.max(1, f.packets) > 200 || f.srcBytes > 20000)) return "DNS Tunneling";
  if (f.srcBytes > 50_000_000) return "Exfiltration";
  if ((f.dport === 443 || f.dport === 80) && f.dstBytes > 5_000_000 && f.duration > 30) return "Streaming";
  return "Normal";
}

const TOP_FEATURES: Record<TrafficClass, [string, number][]> = {
  Normal: [["dst port (80/443)", 0.36], ["flow duration", 0.24], ["ACK flag ratio", 0.18]],
  Streaming: [["dst bytes", 0.44], ["flow duration", 0.27], ["dst port 443", 0.14]],
  DDoS: [["packets/sec", 0.41], ["SYN flag ratio", 0.28], ["unique src IPs", 0.17]],
  "Port Scan": [["unique dst ports", 0.46], ["avg packet size", 0.23], ["RST flag ratio", 0.15]],
  "Brute Force": [["dst port 22", 0.39], ["failed conn. rate", 0.31], ["flow duration", 0.13]],
  Exfiltration: [["src (outbound) bytes", 0.48], ["hour of day", 0.21], ["bytes ratio out/in", 0.16]],
  "DNS Tunneling": [["DNS payload length", 0.43], ["query volume", 0.25], ["dst port 53", 0.15]],
};

function action(cls: TrafficClass, src: string): string {
  switch (cls) {
    case "Normal":
    case "Streaming":
      return "No action required";
    case "DDoS":
      return "Rate-limit source IPs and enable SYN cookies on edge firewall";
    case "Port Scan":
      return `Block source IP ${src} and watch for follow-up exploitation`;
    case "Brute Force":
      return `Block source IP ${src}, enforce SSH key auth and fail2ban`;
    case "Exfiltration":
      return `Isolate host ${src} and terminate outbound session immediately`;
    case "DNS Tunneling":
      return "Sinkhole the queried domain and inspect resolver logs";
  }
}

const MODEL_CONF: Record<ModelName, [number, number, number]> = {
  // min, max, misclassification probability
  "Random Forest": [0.93, 0.995, 0.01],
  "Decision Tree": [0.88, 0.975, 0.03],
  "Logistic Regression": [0.76, 0.92, 0.09],
};

export function classify(f: FlowFeatures, model: ModelName, src = "unknown"): Prediction {
  let cls = ruleClass(f);
  const [lo, hi, miss] = MODEL_CONF[model];
  let conf = rand(lo, hi);
  if (Math.random() < miss) {
    // borderline misclassification
    const neighbours: Partial<Record<TrafficClass, TrafficClass>> = {
      Streaming: "Exfiltration",
      "DNS Tunneling": "Normal",
      "Port Scan": "Normal",
      "Brute Force": "Normal",
      Normal: "Streaming",
      DDoS: "Port Scan",
    };
    cls = neighbours[cls] ?? cls;
    conf = rand(0.52, 0.7);
  }
  const top = TOP_FEATURES[cls].map(([name, v]) => ({
    name,
    value: Math.max(0.02, +(v + rand(-0.03, 0.03)).toFixed(2)),
  }));
  return { cls, conf, ...CLASS_META[cls], top, action: action(cls, src) };
}

export type Scenario =
  | "Normal Browsing"
  | "Video Streaming"
  | "DDoS Attack"
  | "Port Scan"
  | "SSH Brute Force"
  | "Data Exfiltration"
  | "DNS Tunneling"
  | "Mixed Random Traffic";

export const SCENARIOS: { name: Scenario; desc: string; tone: Status }[] = [
  { name: "Normal Browsing", desc: "HTTP/HTTPS · 80/443", tone: "normal" },
  { name: "Video Streaming", desc: "High bytes · long duration", tone: "normal" },
  { name: "DDoS Attack", desc: "SYN flood · many sources", tone: "attack" },
  { name: "Port Scan", desc: "1 source → many ports", tone: "suspicious" },
  { name: "SSH Brute Force", desc: "Failed logins · port 22", tone: "attack" },
  { name: "Data Exfiltration", desc: "Huge outbound · odd hours", tone: "attack" },
  { name: "DNS Tunneling", desc: "Long queries · port 53", tone: "suspicious" },
  { name: "Mixed Random Traffic", desc: "Auto-generated mix", tone: "suspicious" },
];

const F = (syn = false, ack = false, fin = false, rst = false) => ({ syn, ack, fin, rst });

export function genFeatures(s: Scenario): FlowFeatures {
  switch (s) {
    case "Normal Browsing":
      return {
        proto: "TCP", sport: randInt(49152, 65535), dport: pick([80, 443, 443]),
        duration: rand(0.2, 8), srcBytes: randInt(400, 6000), dstBytes: randInt(2000, 400000),
        packets: randInt(8, 120), pps: rand(5, 60), flags: F(true, true, true),
      };
    case "Video Streaming":
      return {
        proto: "TCP", sport: randInt(49152, 65535), dport: 443,
        duration: rand(60, 900), srcBytes: randInt(40000, 300000), dstBytes: randInt(8_000_000, 120_000_000),
        packets: randInt(6000, 90000), pps: rand(80, 300), flags: F(true, true),
      };
    case "DDoS Attack":
      return {
        proto: "TCP", sport: randInt(1024, 65535), dport: pick([80, 443]),
        duration: rand(0.01, 0.4), srcBytes: randInt(40, 120), dstBytes: 0,
        packets: randInt(2000, 9000), pps: rand(2500, 9000), flags: F(true),
      };
    case "Port Scan":
      return {
        proto: "TCP", sport: randInt(40000, 60000), dport: randInt(1, 1024),
        duration: rand(0.001, 0.05), srcBytes: 60, dstBytes: 40,
        packets: 2, pps: rand(200, 600), flags: F(true, false, false, true), uniquePorts: randInt(40, 900),
      };
    case "SSH Brute Force":
      return {
        proto: "TCP", sport: randInt(40000, 60000), dport: 22,
        duration: rand(0.3, 2.5), srcBytes: randInt(800, 3000), dstBytes: randInt(900, 2500),
        packets: randInt(10, 30), pps: rand(10, 40), flags: F(true, true, false, true),
      };
    case "Data Exfiltration":
      return {
        proto: "TCP", sport: randInt(49152, 65535), dport: pick([443, 8443, 21]),
        duration: rand(120, 1800), srcBytes: randInt(60_000_000, 900_000_000), dstBytes: randInt(20000, 200000),
        packets: randInt(40000, 600000), pps: rand(200, 900), flags: F(true, true), hour: randInt(1, 4),
      };
    case "DNS Tunneling":
      return {
        proto: "UDP", sport: randInt(49152, 65535), dport: 53,
        duration: rand(0.05, 1), srcBytes: randInt(25000, 90000), dstBytes: randInt(5000, 30000),
        packets: randInt(60, 200), pps: rand(100, 400), flags: F(),
      };
    case "Mixed Random Traffic":
      return genFeatures(pick(SCENARIOS.slice(0, 7)).name);
  }
}

export function makeFlow(f: FlowFeatures, model: ModelName, id: number, src?: string): Flow {
  const s = src ?? randomIp(f.dport === 22 || f.proto === "UDP" ? false : undefined);
  const p = classify(f, model, s);
  return { ...f, ...p, id, ts: Date.now(), src: s, dst: randomIp(true) };
}

/** Deterministic plausible confusion matrix (6 classes). */
export const CM_CLASSES: TrafficClass[] = ["Normal", "DDoS", "Port Scan", "Brute Force", "Exfiltration", "DNS Tunneling"];
const SUPPORT = [4200, 1800, 1200, 900, 600, 700];
export function confusionMatrix(model: ModelName): number[][] {
  const acc = MODEL_METRICS[model].accuracy / 100;
  const err = 1 - acc;
  // fixed error spread patterns (row-wise weights to other classes)
  const spread = [
    [0, 0.15, 0.3, 0.2, 0.15, 0.2],
    [0.2, 0, 0.6, 0.1, 0.05, 0.05],
    [0.45, 0.35, 0, 0.1, 0.05, 0.05],
    [0.5, 0.1, 0.25, 0, 0.05, 0.1],
    [0.55, 0.05, 0.05, 0.05, 0, 0.3],
    [0.6, 0.05, 0.05, 0.05, 0.25, 0],
  ];
  const rowErr = [0.8, 1.0, 1.3, 1.4, 1.6, 1.5];
  return SUPPORT.map((n, i) => {
    const wrong = Math.round(n * err * rowErr[i]);
    const row = spread[i].map((w) => Math.round(wrong * w));
    row[i] = n - row.reduce((a, b) => a + b, 0);
    return row;
  });
}

export const fmtBytes = (b: number) => {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
  return `${(b / 1024 ** 3).toFixed(2)} GB`;
};

import { createFileRoute } from "@tanstack/react-router";
import Dashboard from "@/components/netguard/Dashboard";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "NetGuard AI — Network Traffic Classification & Monitoring" },
      { name: "description", content: "Simulated ML dashboard that classifies network traffic and detects DDoS, port scans, brute force, exfiltration and DNS tunneling." },
      { property: "og:title", content: "NetGuard AI — Network Traffic Classification" },
      { property: "og:description", content: "Live SOC-style dashboard simulating Random Forest, Decision Tree and Logistic Regression traffic classifiers." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

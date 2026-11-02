import type { CvssSource, Severity } from "@/lib/types";

/**
 * Severity is never colour alone: always the short label + the score,
 * with a 3px colour bar on the left (HANDOFF 4.10).
 */
const SEV: Record<Severity | "UNSCORED", { short: string; bar: string }> = {
  CRITICAL: { short: "CRIT", bar: "bg-sev-critical" },
  HIGH: { short: "HIGH", bar: "bg-sev-high" },
  MEDIUM: { short: "MED", bar: "bg-sev-medium" },
  LOW: { short: "LOW", bar: "bg-sev-low" },
  NONE: { short: "NONE", bar: "bg-sev-none" },
  UNSCORED: { short: "N/A", bar: "bg-sev-none" },
};

export function SeverityTag({ severity, score }: { severity: Severity | null; score?: number | null }) {
  const s = SEV[severity ?? "UNSCORED"];
  const scoreText = score == null ? "" : score.toFixed(1);
  return (
    <span
      className="tl-mono inline-flex items-center gap-1.5 text-xs text-paper"
      title={`${severity ?? "Unscored"}${scoreText ? ` ${scoreText}` : ""}`}
    >
      <span aria-hidden="true" className={`h-3.5 w-[3px] ${s.bar}`} />
      <span>{s.short}</span>
      {scoreText ? <span className={severity === "CRITICAL" ? "text-hazard" : "text-paper-dim"}>{scoreText}</span> : null}
    </span>
  );
}

export function KevTag({ compact = false }: { compact?: boolean }) {
  return (
    <span
      className="tl-mono inline-flex items-center gap-1.5 text-[11px] uppercase tracking-[0.06em] text-hazard"
      title="Listed in CISA's Known Exploited Vulnerabilities catalogue"
    >
      <span aria-hidden="true" className="tl-pulse h-1.5 w-1.5 rounded-full bg-hazard" />
      {compact ? "KEV" : "Known exploited"}
    </span>
  );
}

const SOURCE: Record<CvssSource, { label: string; title: string }> = {
  NVD: { label: "NVD", title: "Scored by NVD analysts" },
  CNA: { label: "Vendor (CNA)", title: "Scored by the organisation that published the CVE, not by NVD" },
  ADP: { label: "CISA (ADP)", title: "Scored by CISA's Authorized Data Publisher, not by NVD" },
};

export function SourceTag({ source }: { source: CvssSource | null }) {
  if (!source) return null;
  const s = SOURCE[source];
  return (
    <span className="tl-mono text-[11px] text-paper-faint" title={s.title}>
      {s.label}
    </span>
  );
}

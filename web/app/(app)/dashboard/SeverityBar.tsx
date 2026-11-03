import type { StatsOverview } from "@/lib/cve";
import { fmtInt, fmtPct } from "../_shared/format";

/**
 * 01 / SEVERITY: one horizontal stacked bar (six groups is too many for a
 * donut), then a legend that doubles as the data table: every group has its
 * label, count, share and average score in text, so nothing is colour-only.
 */
const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNSCORED"] as const;
const STYLE: Record<(typeof ORDER)[number], { bar: string; label: string }> = {
  CRITICAL: { bar: "bg-sev-critical", label: "Critical" },
  HIGH: { bar: "bg-sev-high", label: "High" },
  MEDIUM: { bar: "bg-sev-medium", label: "Medium" },
  LOW: { bar: "bg-sev-low", label: "Low" },
  NONE: { bar: "bg-sev-none", label: "None (0.0)" },
  UNSCORED: { bar: "bg-sev-none", label: "Not scored yet" }, // HANDOFF 4.10: --sev-none = NONE / unscored
};

export function SeverityBar({ rows, total }: { rows: StatsOverview["bySeverity"]; total: number }) {
  const by = new Map(rows.map((r) => [r.severity, r]));
  const groups = ORDER.map((s) => ({ s, count: by.get(s)?.count ?? 0, avg: by.get(s)?.avg_score ?? null }));

  return (
    <div>
      <div className="flex h-7 w-full gap-px bg-rule" aria-hidden="true">
        {groups
          .filter((g) => g.count > 0)
          .map((g) => (
            <div
              key={g.s}
              className={`${STYLE[g.s].bar} h-full`}
              style={{ flexGrow: g.count, flexBasis: 0, minWidth: 2 }}
              title={`${STYLE[g.s].label}: ${fmtInt(g.count)} (${fmtPct(g.count, total)})`}
            />
          ))}
      </div>
      <ul className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3 lg:grid-cols-6" aria-label="CVEs by severity">
        {groups.map((g) => (
          <li key={g.s} className="flex items-start gap-2">
            <span aria-hidden="true" className={`mt-1 h-3 w-[3px] shrink-0 ${STYLE[g.s].bar}`} />
            <span className="min-w-0">
              <span className="block text-[13px] text-paper">{STYLE[g.s].label}</span>
              <span className="tl-mono block text-xs text-paper-dim">
                {fmtInt(g.count)} <span className="text-paper-faint">{fmtPct(g.count, total)}</span>
              </span>
              {g.avg != null && g.s !== "NONE" ? (
                <span className="tl-mono block text-[11px] text-paper-faint">avg {g.avg.toFixed(1)}</span>
              ) : null}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

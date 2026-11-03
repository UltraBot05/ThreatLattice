"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { DataTable } from "@/components/ui/DataTable";
import { Select } from "@/components/ui/Field";
import { KpiStrip } from "@/components/ui/KpiStrip";
import { ErrorState } from "@/components/ui/States";
import { IdText, PageHeader, Panel } from "@/components/ui/Text";
import { Declassify } from "@/components/motion/Declassify";
import { useApi } from "@/lib/client/api";
import type { EventCveRow, StatsOverview } from "@/lib/cve";
import { fmtInt } from "../_shared/format";
import { OverTimeChart } from "./OverTimeChart";
import { SeverityBar } from "./SeverityBar";

/**
 * /dashboard: the state of the CVE data in one screen.
 * KPI strip -> 01 severity -> 02 over time -> 03 top weaknesses.
 * ?year= scopes everything except the year list itself (kept in the URL so
 * a dashboard view can be shared).
 */
const SPOTLIGHT = "black-october-2026";

export function DashboardView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const year = params.get("year") ?? "";

  const stats = useApi<StatsOverview>(`/api/stats/overview${year ? `?year=${encodeURIComponent(year)}` : ""}`);
  const event = useApi<{ event: { name: string }; cves: EventCveRow[] }>(`/api/events/${SPOTLIGHT}`);
  const s = stats.data;

  const setYear = (y: string) => router.replace(y ? `${pathname}?year=${y}` : pathname, { scroll: false });
  const critical = s?.bySeverity.find((r) => r.severity === "CRITICAL")?.count ?? 0;
  const scope = s?.year ? `published in ${s.year}` : "2024 to 2026";

  return (
    <div>
      <PageHeader
        crumb="DASHBOARD"
        title="Dashboard"
        subtitle={`Every CVE in the database, ${scope}, by severity, month and weakness.`}
        actions={
          <label className="flex items-center gap-2">
            <span className="tl-label">Year</span>
            <Select value={year} onChange={(e) => setYear(e.target.value)} className="w-[130px]" aria-label="Year">
              <option value="">All years</option>
              {(s?.byYear ?? [])
                .slice()
                .reverse()
                .map((y) => (
                  <option key={y.year} value={String(y.year)}>
                    {y.year}
                  </option>
                ))}
              {/* keep the chosen year selectable before the list has loaded */}
              {year && !s ? <option value={year}>{year}</option> : null}
            </Select>
          </label>
        }
      />

      {stats.error ? (
        <ErrorState message={stats.error} onRetry={stats.reload} />
      ) : (
        <div className="flex flex-col gap-8">
          <Declassify loading={!s} lines={2}>
            {s ? (
              <KpiStrip
                items={[
                  { label: "Total CVEs", value: s.total, hint: scope },
                  { label: "Critical", value: critical, hint: "CVSS 9.0 to 10.0" },
                  { label: "Known exploited", value: s.kevCount, tone: "hazard", hint: "in CISA's KEV catalogue" },
                  {
                    label: "Black October",
                    value: event.data?.cves.length ?? 0,
                    hint: event.error ? "spotlight unavailable" : "CVEs in the October 2026 spotlight",
                  },
                ]}
              />
            ) : (
              <span />
            )}
          </Declassify>

          <Panel index={1} label="Severity">
            <Declassify loading={!s} lines={2}>
              {s ? <SeverityBar rows={s.bySeverity} total={s.total} /> : <span />}
            </Declassify>
          </Panel>

          <Panel index={2} label="Over time">
            <Declassify loading={!s} lines={5}>
              {s ? <OverTimeChart months={s.byMonth} /> : <span />}
            </Declassify>
          </Panel>

          <Panel index={3} label="Top weaknesses">
            <DataTable
              caption="Top 10 weaknesses by number of CVEs"
              loading={!s}
              rows={s?.topCwes ?? []}
              rowId={(c) => c.cwe_id}
              rowHref={(c) => `/search?cwe=${c.cwe_id}${year ? `&from=${year}-01-01&to=${year}-12-31` : ""}`}
              flipKey={year}
              columns={[
                { key: "id", header: "CWE", width: "96px", render: (c) => <IdText id={c.cwe_id} /> },
                {
                  key: "name",
                  header: "Weakness",
                  render: (c) => (
                    <span className="block truncate" title={c.name}>
                      {c.common_name ?? c.name}
                    </span>
                  ),
                },
                { key: "n", header: "CVEs", width: "80px", align: "right", render: (c) => <span className="tl-mono">{fmtInt(c.count)}</span> },
                {
                  key: "avg",
                  header: "Avg score",
                  width: "88px",
                  align: "right",
                  render: (c) => <span className="tl-mono text-paper-dim">{c.avg_score?.toFixed(1) ?? "n/a"}</span>,
                },
                {
                  key: "kev",
                  header: "KEV",
                  width: "56px",
                  align: "right",
                  render: (c) => <span className={`tl-mono ${c.kev_count ? "text-paper" : "text-paper-faint"}`}>{fmtInt(c.kev_count)}</span>,
                },
              ]}
            />
          </Panel>
        </div>
      )}
    </div>
  );
}

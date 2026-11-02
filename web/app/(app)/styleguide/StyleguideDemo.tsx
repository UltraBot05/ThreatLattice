"use client";

import { useState } from "react";
import { DecodeText, RuleDraw } from "@/components/motion";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorState,
  Field,
  IdText,
  Input,
  KevTag,
  KpiStrip,
  PageHeader,
  Panel,
  Select,
  SeverityTag,
  SourceTag,
  type Column,
} from "@/components/ui";
import type { CvssSource, Severity } from "@/lib/types";

/**
 * Living design reference for both of us (HANDOFF 4.10). Every component and
 * motion primitive in one place. Black October rows use the verified values
 * from HANDOFF section 8; everything else here is sample data.
 */
interface Row {
  id: string;
  note: string;
  score: number;
  severity: Severity;
  source: CvssSource;
  kev: boolean;
}

const ROWS: Row[] = [
  { id: "CVE-2026-110264", note: "GitLab RCE (integer overflow)", score: 10.0, severity: "CRITICAL", source: "CNA", kev: false },
  { id: "CVE-2026-109618", note: "PHP2Shell: RCE via OOM corruption", score: 9.8, severity: "CRITICAL", source: "NVD", kev: true },
  { id: "CVE-2026-104286", note: "FortiMail path traversal", score: 9.8, severity: "CRITICAL", source: "CNA", kev: true },
  { id: "CVE-2026-102764", note: "BeyondTrust auth bypass", score: 9.8, severity: "CRITICAL", source: "NVD", kev: true },
  { id: "CVE-2026-96951", note: "Windows Shell bypass", score: 8.8, severity: "HIGH", source: "CNA", kev: true },
  { id: "CVE-2026-109619", note: "PHP2Shell: stale global state", score: 8.1, severity: "HIGH", source: "NVD", kev: true },
  { id: "CVE-2026-46300", note: "Linux kernel missing init", score: 7.8, severity: "HIGH", source: "NVD", kev: true },
  { id: "CVE-2026-41709", note: "VMware ESX insufficient logging", score: 2.7, severity: "LOW", source: "CNA", kev: true },
];

const columns: Column<Row>[] = [
  { key: "id", header: "CVE", width: "150px", render: (r) => <IdText id={r.id} /> },
  { key: "note", header: "Summary", render: (r) => <span className="block truncate">{r.note}</span> },
  { key: "sev", header: "Severity", width: "110px", render: (r) => <SeverityTag severity={r.severity} score={r.score} /> },
  { key: "src", header: "Source", width: "96px", render: (r) => <SourceTag source={r.source} /> },
  { key: "kev", header: "KEV", width: "70px", align: "right", render: (r) => (r.kev ? <KevTag compact /> : <span className="text-paper-faint">-</span>) },
];

export function StyleguideDemo() {
  const [sort, setSort] = useState<"score" | "id">("score");
  const [kevOnly, setKevOnly] = useState(false);
  const [loading, setLoading] = useState(false);

  const rows = ROWS.filter((r) => !kevOnly || r.kev).sort((a, b) =>
    sort === "score" ? b.score - a.score : a.id.localeCompare(b.id),
  );

  const reload = () => {
    setLoading(true);
    setTimeout(() => setLoading(false), 900);
  };

  return (
    <>
      <PageHeader
        crumb="STYLEGUIDE"
        title={
          <>
            Declassified, <i className="text-paper-dim">the kit</i>
          </>
        }
        subtitle="Every shared component and motion primitive. Pages use these and the tokens in globals.css; nothing else."
        actions={<Button href="/dashboard" variant="primary">Open dashboard</Button>}
      />

      <KpiStrip
        items={[
          { label: "Total CVEs", value: 164370 },
          { label: "Critical", value: 21734, tone: "hazard", hint: "sample value" },
          { label: "Known exploited", value: 547 },
          { label: "Black October", value: 8 },
        ]}
      />

      <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel
          index={1}
          label="Table, Flip and Declassify"
          actions={
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                onClick={() => setSort((s) => (s === "score" ? "id" : "score"))}
              >
                Sort by {sort === "score" ? "ID" : "score"}
              </Button>
              <Button
                size="sm"
                onClick={() => setKevOnly((k) => !k)}
              >
                {kevOnly ? "Show all" : "Known exploited only"}
              </Button>
              <Button size="sm" variant="ghost" onClick={reload}>
                Reload
              </Button>
            </div>
          }
        >
          <DataTable
            caption="Black October 2026 CVEs"
            columns={columns}
            rows={rows}
            rowId={(r) => r.id}
            rowHref={(r) => `/cve/${r.id}`}
            loading={loading}
            flipKey={`${sort}-${kevOnly}`}
          />
        </Panel>

        <div className="flex flex-col gap-8">
          <Panel index={2} label="Identifiers">
            <p className="text-2xl">
              <DecodeText text="CVE-2026-109618" />
            </p>
            <p className="mt-1 text-[13px] text-paper-dim">
              Decodes once on first render. Screen readers get the real text.
            </p>
          </Panel>

          <Panel index={3} label="Tags">
            <div className="flex flex-wrap items-center gap-4">
              <SeverityTag severity="CRITICAL" score={9.8} />
              <SeverityTag severity="HIGH" score={8.1} />
              <SeverityTag severity="MEDIUM" score={5.4} />
              <SeverityTag severity="LOW" score={2.7} />
              <SeverityTag severity={null} />
              <KevTag />
              <SourceTag source="NVD" />
              <SourceTag source="CNA" />
              <SourceTag source="ADP" />
            </div>
          </Panel>

          <Panel index={4} label="Controls">
            <div className="flex flex-col gap-3">
              <Field label="Search descriptions" htmlFor="sg-q">
                <Input id="sg-q" placeholder="remote code execution" />
              </Field>
              <Field label="Severity" htmlFor="sg-sev">
                <Select id="sg-sev" defaultValue="">
                  <option value="">Any</option>
                  <option>CRITICAL</option>
                  <option>HIGH</option>
                </Select>
              </Field>
              <div className="flex gap-2">
                <Button variant="primary">Explore chain</Button>
                <Button>Save investigation</Button>
                <Button variant="ghost">Clear filters</Button>
              </div>
            </div>
          </Panel>
        </div>
      </div>

      <RuleDraw className="my-8" />

      <div className="grid gap-6 md:grid-cols-2">
        <EmptyState message="No CVEs match these filters." action={<Button size="sm">Clear filters</Button>} />
        <ErrorState message="The database could not complete the request." onRetry={reload} />
      </div>
    </>
  );
}

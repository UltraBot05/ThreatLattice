"use client";

import { useState } from "react";
import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button } from "@/components/ui/Button";
import { DataTable } from "@/components/ui/DataTable";
import type { StatsOverview } from "@/lib/cve";
import { fmtInt, fmtMonth } from "../_shared/format";

/**
 * 02 / OVER TIME: CVEs published per month as a quiet area in paper-dim,
 * with the critical ones as a hazard line on top (the only colour on the
 * chart, because only it means danger). Series differ by form too (filled
 * area vs. line), not by hue alone. "Show table" gives the same numbers as
 * a table (HANDOFF 4.10 accessibility).
 * The current calendar month is still filling up, so it is left off the
 * chart (it would look like a collapse) and stated in words underneath.
 */
type Month = StatsOverview["byMonth"][number];

const AXIS = { fontFamily: "var(--font-mono)", fontSize: 11, fill: "var(--color-paper-faint)" };

function Tip({ active, payload }: { active?: boolean; payload?: { payload: Month }[] }) {
  if (!active || !payload?.length) return null;
  const m = payload[0].payload;
  return (
    <div className="border border-rule-strong bg-ink-2 px-3 py-2 text-xs">
      <p className="tl-label">{fmtMonth(m.month)}</p>
      <p className="tl-mono mt-1 text-paper">{fmtInt(m.count)} CVEs</p>
      <p className="tl-mono text-hazard">{fmtInt(m.critical)} critical</p>
    </div>
  );
}

export function OverTimeChart({ months: all }: { months: Month[] }) {
  const [asTable, setAsTable] = useState(false);
  const now = new Date();
  const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  const partial = all.find((m) => m.month === thisMonth) ?? null;
  const months = partial ? all.filter((m) => m !== partial) : all;
  const shortTicks = months.length <= 12;

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <p className="flex items-center gap-4 text-xs text-paper-dim">
          <span className="flex items-center gap-1.5">
            <span aria-hidden="true" className="h-2.5 w-2.5 bg-paper-dim/40" /> All CVEs
          </span>
          <span className="flex items-center gap-1.5">
            <span aria-hidden="true" className="h-[2px] w-3 bg-hazard" /> Critical
          </span>
        </p>
        <Button size="sm" variant="ghost" aria-pressed={asTable} onClick={() => setAsTable((v) => !v)}>
          {asTable ? "Show chart" : "Show table"}
        </Button>
      </div>

      {asTable ? (
        <DataTable
          caption="CVEs per month"
          rows={all}
          rowId={(m) => m.month}
          columns={[
            {
              key: "m",
              header: "Month",
              render: (m) => (
                <span className="tl-mono">
                  {fmtMonth(m.month)}
                  {m === partial ? <span className="text-paper-faint"> so far</span> : null}
                </span>
              ),
            },
            { key: "c", header: "CVEs", align: "right", width: "120px", render: (m) => <span className="tl-mono">{fmtInt(m.count)}</span> },
            {
              key: "k",
              header: "Critical",
              align: "right",
              width: "120px",
              render: (m) => <span className="tl-mono text-hazard">{fmtInt(m.critical)}</span>,
            },
          ]}
        />
      ) : (
        <div className="h-[240px] w-full" role="img" aria-label={`CVEs per month, ${months.length} months. Use Show table for the numbers.`}>
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={months} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid stroke="var(--color-rule)" vertical={false} />
              <XAxis
                dataKey="month"
                tickFormatter={(m: string) => fmtMonth(m, shortTicks)}
                tick={AXIS}
                axisLine={{ stroke: "var(--color-rule)" }}
                tickLine={false}
                minTickGap={24}
              />
              <YAxis tick={AXIS} axisLine={false} tickLine={false} width={48} tickFormatter={(n: number) => fmtInt(n)} />
              <Tooltip content={<Tip />} cursor={{ stroke: "var(--color-rule-strong)" }} isAnimationActive={false} />
              <Area
                type="linear"
                dataKey="count"
                stroke="var(--color-paper-dim)"
                strokeWidth={1}
                fill="var(--color-paper-dim)"
                fillOpacity={0.1}
                isAnimationActive={false}
              />
              <Line type="linear" dataKey="critical" stroke="var(--color-hazard)" strokeWidth={1.5} dot={false} isAnimationActive={false} />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      )}
      {partial && !asTable ? (
        <p className="tl-mono mt-2 text-[11px] text-paper-faint">
          {fmtMonth(partial.month)} so far: {fmtInt(partial.count)} CVEs, {fmtInt(partial.critical)} critical (month not over, not plotted)
        </p>
      ) : null}
    </div>
  );
}

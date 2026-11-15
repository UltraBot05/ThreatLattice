"use client";

import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { Declassify } from "@/components/motion/Declassify";
import { DecodeText } from "@/components/motion/DecodeText";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { IdText, Panel, SectionLabel } from "@/components/ui/Text";
import { useApi } from "@/lib/client/api";
import type { ChainGraph as Chain, GraphNode } from "@/lib/graph";
import { ChainGraph } from "../ChainGraph";
import { NodePanel } from "../NodePanel";

/**
 * /explore/[cveId]?depth=0|1|2 : the attack chain for one CVE (B4).
 * Graph (left) + selected-node panel (right) + the same chains as a table
 * (techniques by tactic) so the result is readable without the graph.
 */
const DEPTHS = [
  { d: 0, label: "Direct only" },
  { d: 1, label: "+1 parent" },
  { d: 2, label: "+2 parents" },
];

interface TechRow {
  id: string;
  name: string;
  tactics: string[];
  via: string;
  chains: number;
}

export function ExploreView() {
  const { cveId: raw } = useParams<{ cveId: string }>();
  const id = decodeURIComponent(raw).toUpperCase();
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const depth = Math.min(2, Math.max(0, Number(params.get("depth") ?? 2) || 0));
  const { data, error, loading, reload } = useApi<Chain>(`/api/chain/${encodeURIComponent(id)}?depth=${depth}`);
  const [selected, setSelected] = useState<string | null>(null);

  const chain = data && data.meta.cve === id && data.meta.depth === depth ? data : null;
  const byId = useMemo(() => new Map(chain?.nodes.map((n) => [n.id, n]) ?? []), [chain]);

  const techRows = useMemo<TechRow[]>(() => {
    if (!chain) return [];
    const rows = new Map<string, TechRow>();
    for (const p of chain.paths) {
      const t = byId.get(p[p.length - 1]) as GraphNode;
      const row = rows.get(t.id) ?? {
        id: t.id,
        name: t.label,
        tactics: (t.props.tactics as string[]) ?? [],
        via: p.slice(1, -1).join(" > "),
        chains: 0,
      };
      row.chains += 1;
      rows.set(t.id, row);
    }
    return [...rows.values()].sort((a, b) => b.chains - a.chains || a.id.localeCompare(b.id));
  }, [chain, byId]);

  const setDepth = (d: number) => {
    setSelected(null);
    router.replace(d === 2 ? pathname : `${pathname}?depth=${d}`, { scroll: false });
  };

  const header = (
    <header className="mb-6 border-b border-rule pb-4">
      <p className="tl-label">THREATLATTICE / EXPLORE</p>
      <div className="mt-2 flex flex-wrap items-end justify-between gap-4">
        <h1 className="tl-mono text-[28px] leading-tight text-paper sm:text-[32px]">
          <DecodeText text={id} />
        </h1>
        <div className="flex gap-2">
          <Button size="sm" href={`/cve/${id}`}>CVE dossier</Button>
        </div>
      </div>
      <p className="mt-2 max-w-[75ch] text-[13px] text-paper-dim">
        What an attacker could do with this vulnerability: its weaknesses, the attack patterns that exploit them, and the ATT&amp;CK techniques those patterns enable.
      </p>
    </header>
  );

  if (error) {
    return (
      <div>
        {header}
        {/not in the database/i.test(error) ? (
          <EmptyState label="NOT FOUND" message={`${id} is not in the database.`} action={<Button size="sm" href="/explore">Try another CVE</Button>} />
        ) : (
          <ErrorState message={error} onRetry={reload} />
        )}
      </div>
    );
  }

  const selectedNode = selected ? byId.get(selected) ?? null : null;
  const columns: Column<TechRow>[] = [
    { key: "id", header: "Technique", width: "110px", render: (r) => <IdText id={r.id} /> },
    { key: "name", header: "Name", render: (r) => <span className="block truncate" title={r.name}>{r.name}</span> },
    { key: "tactics", header: "Tactics", width: "minmax(0,0.8fr)", render: (r) => <span className="tl-mono block truncate text-[12px] text-paper-dim">{r.tactics.join(", ")}</span> },
    { key: "via", header: "Shortest route", width: "minmax(0,1.2fr)", render: (r) => <span className="tl-mono block truncate text-[12px] text-paper-dim" title={r.via}>{r.via}</span> },
    { key: "chains", header: "Chains", width: "64px", align: "right", render: (r) => <span className="tl-mono">{r.chains}</span> },
  ];

  return (
    <div>
      {header}

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Parent weakness levels">
          <span className="tl-label mr-1">PARENT LEVELS</span>
          {DEPTHS.map((o) => (
            <Button key={o.d} size="sm" variant={o.d === depth ? "primary" : "secondary"} aria-pressed={o.d === depth} onClick={() => setDepth(o.d)}>
              {o.label}
            </Button>
          ))}
        </div>
        {chain ? (
          <p className="tl-mono text-[12px] text-paper-dim" aria-live="polite">
            {chain.meta.counts.cwe} CWE · {chain.meta.counts.capec} CAPEC · {chain.meta.counts.technique} TECHNIQUES · {chain.paths.length} CHAINS
            {chain.meta.truncated ? " (first 400 shown)" : ""}
          </p>
        ) : null}
      </div>

      <Declassify loading={loading && !chain} lines={8}>
        {chain && chain.paths.length === 0 ? (
          <EmptyState
            label="NO CHAIN"
            message={
              chain.meta.counts.cwe === 0
                ? "NVD has not mapped this CVE to a weakness yet, so there is nothing to follow."
                : depth < 2
                  ? "No attack pattern targets these weaknesses directly. Try more parent levels."
                  : "No attack pattern in CAPEC targets these weaknesses or their parents."
            }
            action={depth < 2 && chain.meta.counts.cwe > 0 ? <Button size="sm" onClick={() => setDepth(2)}>Show +2 parents</Button> : undefined}
          />
        ) : chain ? (
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            <div className="lg:col-span-9">
              <ChainGraph chain={chain} selected={selected} onSelect={setSelected} />
            </div>
            <aside className="border-t border-rule pt-4 lg:col-span-3 lg:border-l lg:border-t-0 lg:pl-5 lg:pt-0" aria-live="polite">
              <NodePanel chain={chain} node={selectedNode} />
            </aside>
          </div>
        ) : (
          <div className="h-[560px]" />
        )}
      </Declassify>

      {chain && chain.meta.tactics.length > 0 ? (
        <Panel index={1} label="Tactics reached" className="mt-8">
          <ul className="flex flex-wrap gap-x-5 gap-y-2">
            {chain.meta.tactics.map((t) => (
              <li key={t.tactic} className="tl-mono text-[12px]">
                <span className="text-paper">{t.tactic}</span> <span className="text-paper-faint">{t.techniques}</span>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      {techRows.length > 0 ? (
        <section className="mt-8">
          <SectionLabel index={2} className="mb-3">Techniques, as a table</SectionLabel>
          <DataTable
            caption={`ATT&CK techniques reachable from ${id}`}
            columns={columns}
            rows={techRows}
            rowId={(r) => r.id}
            onRowClick={(r) => {
              setSelected(r.id);
              window.scrollTo({ top: 0, behavior: "smooth" });
            }}
          />
        </section>
      ) : null}
    </div>
  );
}

"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/Field";
import { ErrorState } from "@/components/ui/States";
import { SeverityTag } from "@/components/ui/Tags";
import { IdText, PageHeader, Panel } from "@/components/ui/Text";
import { Declassify } from "@/components/motion/Declassify";
import { api, useApi } from "@/lib/client/api";
import type { GraphEdge, GraphNode } from "@/lib/graph";
import type { Severity } from "@/lib/types";

/**
 * /explore : start a chain from any CVE, jump to a Black October CVE, or ask
 * how two catalogue entries are connected (Neo4j shortestPath).
 */
interface EventCve {
  cve_id: string;
  cvss_severity: Severity | null;
  cvss_base_score: number | null;
  note: string | null;
  in_nvd: boolean;
}

const CVE_RE = /^CVE-\d{4}-\d+$/;

export function ExploreHome() {
  const router = useRouter();
  const [cve, setCve] = useState("");
  const [cveErr, setCveErr] = useState<string | null>(null);
  const spotlight = useApi<{ cves: EventCve[] }>("/api/events/black-october-2026");

  const [from, setFrom] = useState("CWE-416");
  const [to, setTo] = useState("T1574.010");
  const [path, setPath] = useState<{ nodes: GraphNode[]; edges: GraphEdge[]; hops: number } | null>(null);
  const [pathErr, setPathErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const go = (e: FormEvent) => {
    e.preventDefault();
    const id = cve.trim().toUpperCase();
    if (!CVE_RE.test(id)) return setCveErr("Enter a CVE ID like CVE-2026-109618.");
    router.push(`/explore/${id}`);
  };

  const findPath = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setPathErr(null);
    try {
      setPath(await api(`/api/path?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`));
    } catch (err) {
      setPath(null);
      setPathErr((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        crumb="EXPLORE"
        title={<>Follow the <i className="text-paper-dim">chain</i></>}
        subtitle="Start from a vulnerability and walk to the weaknesses behind it, the attack patterns that exploit them, and the ATT&CK techniques they enable."
      />

      <div className="grid grid-cols-1 gap-10 lg:grid-cols-2">
        <Panel index={1} label="Start from a CVE">
          <form onSubmit={go} noValidate className="flex flex-col gap-3">
            <Field label="CVE ID" htmlFor="cve" error={cveErr ?? undefined}>
              <Input id="cve" value={cve} placeholder="CVE-2026-109618" onChange={(e) => { setCve(e.target.value); setCveErr(null); }} />
            </Field>
            <Button type="submit" variant="primary" className="self-start">Explore chain</Button>
          </form>

          <p className="tl-label mb-2 mt-8">OR PICK ONE FROM BLACK OCTOBER</p>
          {spotlight.error ? (
            <ErrorState message={spotlight.error} onRetry={spotlight.reload} />
          ) : (
            <Declassify loading={!spotlight.data} lines={6}>
              <ul className="flex flex-col">
                {(spotlight.data?.cves ?? []).filter((c) => c.in_nvd).map((c) => (
                  <li key={c.cve_id}>
                    <button
                      type="button"
                      onClick={() => router.push(`/explore/${c.cve_id}`)}
                      className="grid w-full grid-cols-[9.375rem_6.25rem_minmax(0,1fr)] items-center gap-3 border-b border-rule px-1 py-2 text-left text-[0.8125rem] hover:bg-ink-3"
                    >
                      <IdText id={c.cve_id} />
                      <SeverityTag severity={c.cvss_severity} score={c.cvss_base_score} />
                      <span className="truncate text-paper-dim" title={c.note ?? ""}>{c.note}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </Declassify>
          )}
        </Panel>

        <Panel index={2} label="How are two entries connected?">
          <form onSubmit={findPath} noValidate className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
            <Field label="From" htmlFor="from">
              <Input id="from" value={from} onChange={(e) => setFrom(e.target.value)} placeholder="CWE-416" />
            </Field>
            <Field label="To" htmlFor="to">
              <Input id="to" value={to} onChange={(e) => setTo(e.target.value)} placeholder="T1574.010" />
            </Field>
            <Button type="submit" disabled={busy}>{busy ? "Searching" : "Find path"}</Button>
          </form>
          <p className="mt-2 text-[0.75rem] text-paper-faint">
            Any CVE, CWE, CAPEC or technique ID. Neo4j shortest path over the catalogue links (a CVE only at either end), up to 8 hops, in either direction: read it as a connection, not an attack order.
          </p>
          <div className="mt-5" aria-live="polite">
            {pathErr ? <ErrorState message={pathErr} /> : null}
            {path ? (
              <ol className="flex flex-col">
                {path.nodes.map((n, i) => (
                  <li key={n.id} className="grid grid-cols-[1.75rem_7.5rem_minmax(0,1fr)] items-baseline gap-2 border-b border-rule py-2 text-[0.8125rem]">
                    <span className="tl-mono text-[0.6875rem] text-paper-faint">{String(i).padStart(2, "0")}</span>
                    <span className="tl-mono text-paper">{n.id}</span>
                    <span className="truncate text-paper-dim" title={n.label}>
                      {n.label}
                      {i < path.edges.length ? <span className="tl-mono ml-2 text-[0.625rem] text-paper-faint">{path.edges[i].type}</span> : null}
                    </span>
                  </li>
                ))}
                <li className="tl-mono pt-2 text-[0.6875rem] text-paper-faint">{path.hops} HOPS</li>
              </ol>
            ) : null}
          </div>
        </Panel>
      </div>
    </>
  );
}

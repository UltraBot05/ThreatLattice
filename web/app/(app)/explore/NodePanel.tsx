import Link from "next/link";
import type { ChainGraph, GraphNode } from "@/lib/graph";
import { SeverityTag } from "@/components/ui/Tags";
import type { Severity } from "@/lib/types";

/** Official pages for each catalogue entry. */
function externalUrl(n: GraphNode): string | null {
  const num = n.id.split("-")[1];
  if (n.type === "CWE") return `https://cwe.mitre.org/data/definitions/${num}.html`;
  if (n.type === "CAPEC") return `https://capec.mitre.org/data/definitions/${num}.html`;
  if (n.type === "Technique") return `https://attack.mitre.org/techniques/${n.id.replace(".", "/")}/`;
  return null;
}

const TYPE_NAME = { CVE: "Vulnerability", CWE: "Weakness", CAPEC: "Attack pattern", Technique: "ATT&CK technique" };

/** Side panel: what the selected node is, how many chains pass through it, where to read more. */
export function NodePanel({ chain, node }: { chain: ChainGraph; node: GraphNode | null }) {
  if (!node) {
    return (
      <div className="text-[0.8125rem] leading-6 text-paper-dim">
        <p className="tl-label mb-2">HOW TO READ IT</p>
        <p>Left to right: the vulnerability, the weakness it is an instance of, broader parent weaknesses, the attack patterns that exploit them, and the ATT&amp;CK techniques those patterns enable.</p>
        <p className="mt-3">Select any node to highlight every chain through it. Drag to pan, scroll to zoom.</p>
        <ul className="mt-4 flex flex-col gap-1.5 text-[0.75rem]">
          <li>&#9633; CVE &nbsp; &#9671; CWE &nbsp; &#11041; CAPEC &nbsp; &#9675; Technique</li>
        </ul>
      </div>
    );
  }
  const through = chain.paths.filter((p) => p.includes(node.id)).length;
  const url = externalUrl(node);
  const p = node.props;
  return (
    <div className="flex flex-col gap-4 text-[0.8125rem]">
      <div>
        <p className="tl-label">{TYPE_NAME[node.type]}</p>
        <p className="tl-mono mt-1 text-lg text-paper">{node.id}</p>
        {node.type !== "CVE" ? <p className="mt-1 leading-5 text-paper">{node.label}</p> : null}
        {node.type === "CWE" && p.common_name && p.name !== p.common_name ? (
          <p className="mt-1 text-[0.75rem] leading-5 text-paper-dim">{String(p.name)}</p>
        ) : null}
      </div>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5">
        {node.type === "CVE" ? (
          <>
            <dt className="tl-label self-center">Severity</dt>
            <dd><SeverityTag severity={(p.severity as Severity) ?? null} score={(p.score as number) ?? null} /></dd>
            <dt className="tl-label self-center">Exploited</dt>
            <dd className={p.is_kev ? "text-hazard" : "text-paper-dim"}>{p.is_kev ? "Yes (CISA KEV)" : "Not known"}</dd>
          </>
        ) : null}
        {node.type === "CWE" && p.abstraction ? (
          <>
            <dt className="tl-label self-center">Level</dt>
            <dd>{String(p.abstraction)}</dd>
          </>
        ) : null}
        {node.type === "CAPEC" ? (
          <>
            <dt className="tl-label self-center">Severity</dt>
            <dd>{p.severity ? String(p.severity).toLowerCase() : "not rated"}</dd>
            <dt className="tl-label self-center">Likelihood</dt>
            <dd>{p.likelihood ? String(p.likelihood).toLowerCase() : "not rated"}</dd>
          </>
        ) : null}
        {node.type === "Technique" ? (
          <>
            <dt className="tl-label self-center">Tactics</dt>
            <dd className="tl-mono text-[0.75rem]">{((p.tactics as string[]) ?? []).join(", ") || "none"}</dd>
          </>
        ) : null}
        <dt className="tl-label self-center">Chains</dt>
        <dd className="tl-mono">{through}</dd>
      </dl>
      <div className="flex flex-col gap-1.5">
        {node.type === "CVE" ? (
          <Link className="text-paper underline underline-offset-4 hover:text-hazard" href={`/cve/${node.id}`}>Open the CVE dossier</Link>
        ) : null}
        {node.type === "CWE" ? (
          <Link className="text-paper underline underline-offset-4 hover:text-hazard" href={`/search?cwe=${node.id}`}>CVEs with this weakness</Link>
        ) : null}
        {url ? (
          <a className="text-paper-dim underline underline-offset-4 hover:text-hazard" href={url} target="_blank" rel="noopener noreferrer">
            Official MITRE page
          </a>
        ) : null}
      </div>
    </div>
  );
}

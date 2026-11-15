import Link from "next/link";
import { Headline, RevealOnScroll, RuleDraw, SmoothScroll } from "@/components/motion";
import { buttonClass, LogoMark } from "@/components/ui";
import { ChainDiagram } from "./_landing/ChainDiagram";

/** Public landing page (B6): what ThreatLattice answers, how, and where to start. */
const PARTS = [
  {
    n: "01",
    title: "Four catalogues, one question",
    body: "CVE lists real vulnerabilities, CWE the kinds of mistake behind them, CAPEC the patterns attackers use against those mistakes, and MITRE ATT&CK what attackers have actually been seen doing. They are maintained by different groups on different sites. ThreatLattice loads all four and joins them, so “I found this CVE in a scan, what could an attacker do with it?” becomes one query instead of an afternoon of tabs.",
  },
  {
    n: "02",
    title: "Two databases, each doing its job",
    body: "MySQL holds the records: scores, dates, severity, affected products, users and saved work, with full-text search, views, a stored procedure and audit triggers. Neo4j holds the links between catalogues, where a five-hop chain is one pattern instead of a stack of joins, and a shortest path between any two entries is one call.",
  },
  {
    n: "03",
    title: "Weaknesses have parents",
    body: "A CVE is usually tagged with a very specific weakness, while attack patterns are written against broader ones. Following up to two parent levels is what lets about nine in ten CVEs reach an ATT&CK technique, against about a third when only direct links count.",
  },
];

export default function Home() {
  return (
    <SmoothScroll>
      <main className="mx-auto max-w-[72rem] px-6">
        <header className="flex items-center justify-between py-6">
          <span className="flex items-center gap-2.5">
            <LogoMark />
            <span className="font-display text-[1.375rem] leading-none">ThreatLattice</span>
          </span>
          <Link href="/login" className={buttonClass("secondary", "sm")}>Sign in</Link>
        </header>

        <section className="flex min-h-[78dvh] flex-col justify-center gap-7 py-16">
          <p className="tl-label">CVE / CWE / CAPEC / ATT&amp;CK</p>
          <Headline className="max-w-[18ch] text-[2.75rem] leading-[1.02] sm:text-[4.5rem]">
            From a CVE to the attack it <i className="text-paper-dim">enables.</i>
          </Headline>
          <p className="max-w-[60ch] text-[1rem] leading-7 text-paper-dim">
            A security knowledge graph that walks from a vulnerability to the weakness behind it, the attack patterns that exploit it, and the
            techniques attackers use, in one step.
          </p>
          <div className="flex flex-wrap gap-2">
            <Link href="/login?next=/dashboard" className={buttonClass("primary")}>Open the console</Link>
            <Link href="/login?next=/spotlight/black-october-2026" className={buttonClass("secondary")}>Black October 2026</Link>
          </div>
        </section>

        <RevealOnScroll className="pb-16">
          <ChainDiagram />
        </RevealOnScroll>

        {PARTS.map((p) => (
          <section key={p.n} className="py-10">
            <RuleDraw />
            <RevealOnScroll className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-12">
              <p className="tl-label md:col-span-2">{p.n}</p>
              <h2 className="font-display text-[2rem] leading-tight md:col-span-4">{p.title}</h2>
              <p className="text-[0.9375rem] leading-7 text-paper-dim md:col-span-6">{p.body}</p>
            </RevealOnScroll>
          </section>
        ))}

        <section className="py-16">
          <RuleDraw strong />
          <RevealOnScroll className="mt-8 flex flex-col items-start gap-5">
            <p className="tl-label text-hazard">SPOTLIGHT</p>
            <h2 className="max-w-[24ch] font-display text-[2.5rem] leading-tight">Black October: eight disclosures, one month, followed to their techniques.</h2>
            <Link href="/login?next=/spotlight/black-october-2026" className={buttonClass("primary")}>Read the spotlight</Link>
          </RevealOnScroll>
        </section>

        <footer className="tl-mono flex flex-wrap justify-between gap-3 border-t border-rule py-6 text-[0.6875rem] text-paper-faint">
          <span>PES UNIVERSITY · DBMS LEVEL 3 · SECTION 5A</span>
          <span>ABHIGYAN DUTTA · AKSHANSH AGRAWAL</span>
        </footer>
      </main>
    </SmoothScroll>
  );
}

"use client";

import { useParams } from "next/navigation";
import { useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { KevTag, SeverityTag } from "@/components/ui/Tags";
import { IdText } from "@/components/ui/Text";
import { Declassify } from "@/components/motion/Declassify";
import { gsap, MOTION_OK, ScrollTrigger, useGSAP } from "@/components/motion/gsap";
import { Headline } from "@/components/motion/Headline";
import { RevealOnScroll } from "@/components/motion/RevealOnScroll";
import { useApi } from "@/lib/client/api";
import type { EventCveRow } from "@/lib/cve";
import { fmtDate, fmtInt } from "../../_shared/format";

/**
 * /spotlight/[slug]: one security event told as a timeline.
 * Hero (serif title, dates, summary) -> pinned counter on the left while the
 * CVE entries scroll past on the right; the rail beside the entries fills in
 * hazard as you read down. Entries are in publication order; CVEs NVD has not
 * published yet come last, behind a redaction bar.
 */
interface EventInfo {
  slug: string;
  name: string;
  starts_on: string;
  ends_on: string;
  summary: string | null;
}

export function Spotlight() {
  const { slug } = useParams<{ slug: string }>();
  const { data, error, reload } = useApi<{ event: EventInfo; cves: EventCveRow[] }>(`/api/events/${encodeURIComponent(slug)}`);

  const entries = useMemo(
    () =>
      (data?.cves ?? [])
        .slice()
        .sort((a, b) => (a.published_date ?? "9999").localeCompare(b.published_date ?? "9999") || a.cve_id.localeCompare(b.cve_id)),
    [data],
  );

  if (error) {
    return /No event called/i.test(error) ? (
      <EmptyState
        label="NOT FOUND"
        message={`There is no spotlight called ${slug}.`}
        action={
          <Button size="sm" href="/spotlight/black-october-2026">
            Open Black October
          </Button>
        }
      />
    ) : (
      <ErrorState message={error} onRetry={reload} />
    );
  }

  const e = data?.event;
  const kev = entries.filter((c) => c.is_kev).length;
  const critical = entries.filter((c) => c.cvss_severity === "CRITICAL").length;

  return (
    <article>
      {/* Hero */}
      <header className="border-b border-rule pb-10 pt-4 sm:pt-10">
        <p className="tl-label">THREATLATTICE / INTEL / SPOTLIGHT</p>
        <Declassify loading={!e} lines={3} className="mt-6">
          {e ? (
            <div>
              <Headline className="text-[48px] leading-[52px] sm:text-[56px] sm:leading-[60px]">{e.name}</Headline>
              <p className="tl-mono mt-4 text-[13px] text-paper-dim">
                {fmtDate(e.starts_on)} to {fmtDate(e.ends_on)}
              </p>
              {e.summary ? <p className="mt-4 max-w-[62ch] text-base leading-7 text-paper">{e.summary}</p> : null}
            </div>
          ) : (
            <span />
          )}
        </Declassify>
        {data ? (
          <dl className="mt-8 grid max-w-[560px] grid-cols-3 border-y border-rule">
            <Stat label="CVEs" value={entries.length} />
            <Stat label="Known exploited" value={kev} hazard />
            <Stat label="Critical" value={critical} />
          </dl>
        ) : null}
      </header>

      {data ? <Timeline entries={entries} /> : null}

      {data ? (
        <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-rule py-6">
          <p className="text-[13px] text-paper-dim">Every CVE CISA lists as exploited, not just this month.</p>
          <Button size="sm" href="/search?kev=true&sort=newest">
            Search known exploited CVEs
          </Button>
        </footer>
      ) : null}
    </article>
  );
}

function Stat({ label, value, hazard = false }: { label: string; value: number; hazard?: boolean }) {
  return (
    <div className="border-l border-rule px-3 py-3 first:border-l-0 first:pl-0">
      <dt className="tl-label">{label}</dt>
      <dd className={`tl-mono mt-1 text-2xl ${hazard ? "text-hazard" : "text-paper"}`}>{fmtInt(value)}</dd>
    </div>
  );
}

function Timeline({ entries }: { entries: EventCveRow[] }) {
  const root = useRef<HTMLElement>(null);
  const [active, setActive] = useState(0);

  useGSAP(
    () => {
      const el = root.current;
      if (!el) return;
      const list = el.querySelector<HTMLElement>("[data-list]");
      const fill = el.querySelector<HTMLElement>("[data-fill]");
      const aside = el.querySelector<HTMLElement>("[data-aside]");
      if (!list || !fill || !aside) return;

      const mm = gsap.matchMedia();
      // Rail fill follows the reading position (scrub 0.5 = a short catch-up, not a jump).
      mm.add(MOTION_OK, () => {
        gsap.fromTo(
          fill,
          { scaleY: 0 },
          { scaleY: 1, ease: "none", scrollTrigger: { trigger: list, start: "top 65%", end: "bottom 65%", scrub: 0.5 } },
        );
      });
      mm.add("(prefers-reduced-motion: reduce)", () => {
        gsap.set(fill, { scaleY: 1 });
      });
      // Pin the counter column beside the list on wide screens only; phones read it inline.
      mm.add(`${MOTION_OK} and (min-width: 768px)`, () => {
        ScrollTrigger.create({ trigger: list, start: "top 96px", end: "bottom bottom", pin: aside, pinSpacing: false });
      });
      // Which entry is being read: drives the "03 / 08" counter.
      el.querySelectorAll<HTMLElement>("[data-entry]").forEach((entry, i) => {
        ScrollTrigger.create({
          trigger: entry,
          start: "top 65%",
          end: "bottom 65%",
          onToggle: (self) => self.isActive && setActive(i),
        });
      });
    },
    { scope: root, dependencies: [entries.length] },
  );

  const pad = (n: number) => String(n).padStart(2, "0");

  return (
    <section ref={root} aria-label="Timeline" className="grid grid-cols-1 gap-6 py-10 md:grid-cols-12">
      <div className="md:col-span-3">
        <div data-aside>
          <p className="tl-label">Timeline</p>
          <p className="tl-mono mt-2 text-[32px] leading-none text-paper" aria-hidden="true">
            {pad(active + 1)} <span className="text-paper-faint">/ {pad(entries.length)}</span>
          </p>
          <p className="mt-3 max-w-[28ch] text-xs text-paper-dim">In order of publication. Open any CVE to see what an attacker could do with it.</p>
        </div>
      </div>

      <div data-list className="relative md:col-span-9">
        <div aria-hidden="true" className="absolute bottom-0 left-0 top-0 w-px bg-rule">
          <div data-fill className="h-full w-full origin-top bg-hazard" />
        </div>
        <ol>
          {entries.map((c) => (
            <li key={c.cve_id} data-entry className="border-b border-rule pl-6 last:border-b-0 sm:pl-8">
              <RevealOnScroll className="grid grid-cols-1 gap-x-6 gap-y-2 py-6 sm:grid-cols-[120px_1fr]">
                <p className="tl-mono pt-0.5 text-xs text-paper-dim">
                  <span className="tl-label block text-[10px] text-paper-faint">Published</span>
                  {c.in_nvd ? fmtDate(c.published_date) : <span className="text-paper-faint">Not yet</span>}
                </p>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
                    <IdText id={c.cve_id} href={c.in_nvd ? `/cve/${c.cve_id}` : undefined} className="text-[15px] text-paper" />
                    {c.in_nvd ? (
                      <>
                        <SeverityTag severity={c.cvss_severity} score={c.cvss_base_score} />
                        {c.is_kev ? <KevTag /> : null}
                      </>
                    ) : (
                      <span className="flex items-center gap-2">
                        <span aria-hidden="true" className="inline-block h-3.5 w-24 bg-redact" />
                        <span className="tl-label">Awaiting NVD data</span>
                      </span>
                    )}
                  </div>
                  {c.note ? <p className="mt-2 max-w-[68ch] text-[14px] leading-6 text-paper">{c.note}</p> : null}
                  {c.in_nvd && c.cwes.length ? (
                    <p className="tl-mono mt-1 text-[11px] text-paper-faint">{c.cwes.join("  ")}</p>
                  ) : null}
                  {c.in_nvd ? (
                    <Button size="sm" href={`/explore/${c.cve_id}`} className="mt-3">
                      Explore chain
                    </Button>
                  ) : null}
                </div>
              </RevealOnScroll>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

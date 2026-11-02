import Link from "next/link";
import { Headline } from "@/components/motion";
import { buttonClass, LogoMark } from "@/components/ui";

/** Temporary landing page. The full landing (hero, motion story) is B6. */
export default function Home() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-[1100px] flex-col justify-center gap-6 px-6 py-16">
      <p className="tl-label flex items-center gap-2">
        <LogoMark size={16} /> THREATLATTICE
      </p>
      <Headline className="text-[44px] leading-[1.02] sm:text-[64px]">
        From a CVE to the attack it <i className="text-paper-dim">enables.</i>
      </Headline>
      <p className="max-w-[60ch] text-[15px] leading-6 text-paper-dim">
        ThreatLattice links four public catalogues (CVE, CWE, CAPEC and MITRE ATT&amp;CK) so one query walks
        from a vulnerability to the weakness behind it, the attack patterns that exploit it, and the techniques
        attackers use.
      </p>
      <div className="flex flex-wrap gap-2">
        <Link href="/dashboard" className={buttonClass("primary")}>
          Open dashboard
        </Link>
        <Link href="/styleguide" className={buttonClass("secondary")}>
          View styleguide
        </Link>
      </div>
    </main>
  );
}

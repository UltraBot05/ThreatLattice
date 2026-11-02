import Link from "next/link";
import { LogoMark } from "@/components/ui/Logo";

/** Centered, sidebar-free layout for sign in / register. */
export default function AuthLayout({ children }: LayoutProps<"/">) {
  return (
    <main className="grid min-h-dvh lg:grid-cols-[minmax(0,1fr)_minmax(0,480px)]">
      <section className="hidden flex-col justify-between border-r border-rule bg-rail p-10 lg:flex">
        <Link href="/" className="flex items-center gap-2.5">
          <LogoMark />
          <span className="font-display text-[22px] leading-none">ThreatLattice</span>
        </Link>
        <div>
          <p className="tl-label">CVE / CWE / CAPEC / ATT&amp;CK</p>
          <p className="mt-3 max-w-[22ch] font-display text-[44px] leading-[1.02]">
            Follow a vulnerability to the attack it <i className="text-paper-dim">enables.</i>
          </p>
        </div>
        <p className="tl-mono text-[11px] text-paper-faint">PES UNIVERSITY / DBMS / SECTION 5A</p>
      </section>
      <section className="flex flex-col justify-center px-6 py-12 sm:px-10">{children}</section>
    </main>
  );
}

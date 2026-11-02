import Link from "next/link";
import type { ReactNode } from "react";
import { DecodeText } from "@/components/motion/DecodeText";
import { Headline } from "@/components/motion/Headline";

/** Mono identifier (CVE / CWE / CAPEC / T-id). decode = scramble in once. */
export function IdText({
  id,
  href,
  decode = false,
  className = "",
}: {
  id: string;
  href?: string;
  decode?: boolean;
  className?: string;
}) {
  const inner = decode ? <DecodeText text={id} /> : <span className="tl-mono">{id}</span>;
  if (!href) return <span className={className}>{inner}</span>;
  return (
    <Link href={href} className={`underline-offset-4 hover:text-hazard hover:underline ${className}`}>
      {inner}
    </Link>
  );
}

/** "01 / SEVERITY" section label. */
export function SectionLabel({ index, children, className = "" }: { index?: number; children: ReactNode; className?: string }) {
  return (
    <p className={`tl-label ${className}`}>
      {index != null ? `${String(index).padStart(2, "0")} / ` : ""}
      {children}
    </p>
  );
}

/**
 * Every page starts with this: mono breadcrumb, serif title, one plain
 * sentence, optional actions on the right, then a hairline.
 */
export function PageHeader({
  crumb,
  title,
  subtitle,
  actions,
}: {
  crumb: string;
  title: ReactNode;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-6 border-b border-rule pb-4">
      <p className="tl-label">THREATLATTICE / {crumb}</p>
      <div className="mt-2 flex flex-wrap items-end justify-between gap-4">
        <Headline className="text-[34px] leading-[1.05] sm:text-[40px]">{title}</Headline>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </div>
      {subtitle ? <p className="mt-2 max-w-[70ch] text-[13px] text-paper-dim">{subtitle}</p> : null}
    </header>
  );
}

/** A ruled section (no floating card): optional label, then content. */
export function Panel({
  label,
  index,
  children,
  className = "",
  actions,
}: {
  label?: string;
  index?: number;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <section className={`border-t border-rule pt-3 ${className}`}>
      {label || actions ? (
        <div className="mb-3 flex items-center justify-between gap-3">
          {label ? <SectionLabel index={index}>{label}</SectionLabel> : <span />}
          {actions}
        </div>
      ) : null}
      {children}
    </section>
  );
}

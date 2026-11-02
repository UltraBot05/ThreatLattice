import Link from "next/link";
import type { ButtonHTMLAttributes, ReactNode } from "react";

/**
 * primary = the ONE hazard action per view ("Explore chain"). secondary = outline.
 * ghost = text-only. Pass href to render a link styled as a button.
 */
type Variant = "primary" | "secondary" | "ghost";
type Size = "sm" | "md";

const base =
  "inline-flex items-center justify-center gap-2 rounded-[2px] font-medium transition-colors duration-150 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 whitespace-nowrap";
const variants: Record<Variant, string> = {
  primary: "bg-hazard text-ink hover:bg-[color-mix(in_srgb,var(--color-hazard)_88%,white)]",
  secondary: "border border-rule-strong text-paper hover:bg-ink-3",
  ghost: "text-paper-dim hover:text-paper hover:bg-ink-3",
};
const sizes: Record<Size, string> = { sm: "h-7 px-2.5 text-xs", md: "h-9 px-3.5 text-[13px]" };

export function buttonClass(variant: Variant = "secondary", size: Size = "md", extra = "") {
  return `${base} ${variants[variant]} ${sizes[size]} ${extra}`;
}

export function Button({
  variant = "secondary",
  size = "md",
  className = "",
  href,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: Size;
  href?: string;
  children: ReactNode;
}) {
  if (href) {
    return (
      <Link href={href} className={buttonClass(variant, size, className)}>
        {children}
      </Link>
    );
  }
  return (
    <button type="button" className={buttonClass(variant, size, className)} {...rest}>
      {children}
    </button>
  );
}

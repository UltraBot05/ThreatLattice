"use client";

import { useRef, type ReactNode } from "react";
import { gsap, MOTION_OK, SplitText, useGSAP } from "./gsap";

/**
 * Serif page title that rises in line by line behind a mask (SplitText).
 * Hidden until split to avoid a flash; reduced motion shows it immediately.
 */
export function Headline({
  children,
  as: Tag = "h1",
  className = "",
}: {
  children: ReactNode;
  as?: "h1" | "h2";
  className?: string;
}) {
  const ref = useRef<HTMLHeadingElement>(null);
  useGSAP(
    () => {
      const el = ref.current;
      if (!el) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        const split = SplitText.create(el, {
          type: "lines",
          mask: "lines",
          autoSplit: true,
          onSplit(self) {
            el.classList.remove("tl-headline-pending");
            return gsap.from(self.lines, { yPercent: 100, duration: 0.7, ease: "expo.out", stagger: 0.08 });
          },
        });
        return () => split.revert();
      });
      mm.add("(prefers-reduced-motion: reduce)", () => {
        el.classList.remove("tl-headline-pending");
      });
    },
    { scope: ref },
  );
  return (
    <Tag ref={ref} className={`tl-headline-pending font-display text-paper ${className}`}>
      {children}
    </Tag>
  );
}

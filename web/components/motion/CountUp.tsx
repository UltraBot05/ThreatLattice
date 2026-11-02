"use client";

import { useRef } from "react";
import { gsap, MOTION_OK, useGSAP } from "./gsap";

/** KPI number that counts up from 0 once when it scrolls into view. Tabular digits so width never jumps. */
export function CountUp({
  value,
  decimals = 0,
  className = "",
}: {
  value: number;
  decimals?: number;
  className?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const fmt = (n: number) =>
    n.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });

  useGSAP(
    () => {
      const el = ref.current;
      if (!el) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        const obj = { n: 0 };
        el.textContent = fmt(0);
        gsap.to(obj, {
          n: value,
          duration: 1,
          ease: "power3.out",
          scrollTrigger: { trigger: el, start: "top 95%", once: true },
          onUpdate: () => {
            el.textContent = fmt(obj.n);
          },
        });
      });
    },
    { dependencies: [value], scope: ref },
  );

  return (
    <span ref={ref} className={`tl-mono ${className}`} aria-label={fmt(value)}>
      {fmt(value)}
    </span>
  );
}

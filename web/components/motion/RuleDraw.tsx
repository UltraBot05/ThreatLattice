"use client";

import { useRef } from "react";
import { gsap, MOTION_OK, useGSAP } from "./gsap";

/** A 1px hairline that draws across when it enters the viewport. */
export function RuleDraw({ className = "", strong = false }: { className?: string; strong?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        gsap.from(ref.current, {
          scaleX: 0,
          transformOrigin: "left center",
          duration: 0.6,
          ease: "power2.out",
          scrollTrigger: { trigger: ref.current, start: "top 85%", once: true },
        });
      });
    },
    { scope: ref },
  );
  return <div ref={ref} aria-hidden="true" className={`h-px ${strong ? "bg-rule-strong" : "bg-rule"} ${className}`} />;
}

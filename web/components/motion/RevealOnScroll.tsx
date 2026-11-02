"use client";

import { useRef, type ReactNode } from "react";
import { gsap, MOTION_OK, useGSAP } from "./gsap";

/** Fades a block up 12px once when it scrolls into view (long pages like the spotlight). */
export function RevealOnScroll({ children, className = "" }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        gsap.from(ref.current, {
          y: 12,
          autoAlpha: 0,
          duration: 0.4,
          ease: "power1.out",
          scrollTrigger: { trigger: ref.current, start: "top 90%", once: true },
        });
      });
    },
    { scope: ref },
  );
  return (
    <div ref={ref} className={className}>
      {children}
    </div>
  );
}

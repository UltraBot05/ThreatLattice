"use client";

import { useRef, type ReactNode } from "react";
import { gsap, MOTION_OK, useGSAP } from "./gsap";

/**
 * The signature loading state. While `loading`, black redaction bars stand in
 * for the content. When data arrives the content renders under a stack of
 * bars that wipe away right-to-left ("declassified").
 * Use instead of a spinner for every data view (HANDOFF 4.10).
 */
const WIDTHS = [92, 78, 86, 64, 88, 72, 81, 58, 90, 69];

export function Declassify({
  loading,
  children,
  lines = 3,
  className = "",
  label = "Loading",
}: {
  loading: boolean;
  children: ReactNode;
  lines?: number;
  className?: string;
  label?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useGSAP(
    () => {
      if (loading) return;
      const bars = ref.current?.querySelectorAll<HTMLElement>("[data-redact]");
      if (!bars?.length) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        gsap.fromTo(
          bars,
          { scaleX: 1 },
          {
            scaleX: 0,
            transformOrigin: "right center",
            duration: 0.5,
            ease: "expo.inOut",
            stagger: 0.03,
            onComplete: () => gsap.set(bars, { display: "none" }),
          },
        );
      });
      mm.add("(prefers-reduced-motion: reduce)", () => {
        gsap.set(bars, { display: "none" });
      });
    },
    { dependencies: [loading], scope: ref },
  );

  if (loading) {
    return (
      <div className={`flex flex-col gap-2 ${className}`} aria-busy="true" aria-label={label} role="status">
        {Array.from({ length: lines }, (_, i) => (
          <div key={i} className="h-3.5 bg-redact" style={{ width: `${WIDTHS[i % WIDTHS.length]}%` }} />
        ))}
      </div>
    );
  }

  return (
    <div ref={ref} className={`relative ${className}`}>
      {children}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 flex flex-col">
        {Array.from({ length: lines }, (_, i) => (
          <div key={i} data-redact className="flex-1 bg-redact" />
        ))}
      </div>
    </div>
  );
}

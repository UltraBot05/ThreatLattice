"use client";

import { useRef } from "react";
import { gsap, MOTION_OK, useGSAP } from "./gsap";

/**
 * An identifier or number that "decodes" into place once, on first render
 * (ScrambleText). Screen readers and copy/paste always get the real text.
 * Only for IDs (CVE-2026-109618) and KPI values, never for sentences.
 */
export function DecodeText({ text, className = "" }: { text: string; className?: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        gsap.to(ref.current, {
          duration: 0.6,
          ease: "none",
          scrambleText: { text, chars: "0123456789ABCDEF-", revealDelay: 0.15, speed: 0.6 },
        });
      });
    },
    { dependencies: [text], scope: ref },
  );
  return (
    <span ref={ref} className={`tl-mono ${className}`} aria-label={text}>
      {text}
    </span>
  );
}

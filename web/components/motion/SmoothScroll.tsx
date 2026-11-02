"use client";

import { useEffect, type ReactNode } from "react";
import Lenis from "lenis";
import { gsap, prefersReducedMotion, ScrollTrigger } from "./gsap";

/**
 * Lenis smooth scrolling, synced with ScrollTrigger. Only for the landing page
 * and spotlight pages (HANDOFF 4.10); data pages keep native scrolling.
 */
export function SmoothScroll({ children }: { children: ReactNode }) {
  useEffect(() => {
    if (prefersReducedMotion()) return;
    const lenis = new Lenis({ lerp: 0.1 });
    lenis.on("scroll", ScrollTrigger.update);
    const tick = (time: number) => lenis.raf(time * 1000);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);
    return () => {
      gsap.ticker.remove(tick);
      lenis.destroy();
    };
  }, []);
  return <>{children}</>;
}

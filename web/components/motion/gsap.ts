"use client";

import { gsap } from "gsap";
import { DrawSVGPlugin } from "gsap/DrawSVGPlugin";
import { Flip } from "gsap/Flip";
import { ScrambleTextPlugin } from "gsap/ScrambleTextPlugin";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { SplitText } from "gsap/SplitText";
import { useGSAP } from "@gsap/react";

/**
 * Register every GSAP plugin once. Import gsap and plugins from HERE, never
 * from "gsap/..." directly, so registration always happened first.
 * All GSAP plugins are free since 3.13 (Webflow).
 */
gsap.registerPlugin(useGSAP, ScrollTrigger, SplitText, ScrambleTextPlugin, Flip, DrawSVGPlugin);

/** Use inside useGSAP: mm.add(MOTION_OK, () => { ...animations... }). Reduced motion = no animation, final state. */
export const MOTION_OK = "(prefers-reduced-motion: no-preference)";
export const MOTION_REDUCED = "(prefers-reduced-motion: reduce)";

export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia(MOTION_REDUCED).matches;
}

export { gsap, ScrollTrigger, SplitText, Flip, useGSAP };

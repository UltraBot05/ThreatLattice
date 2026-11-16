"use client";

import { type RefObject, useEffect, useState } from "react";

/**
 * Sizes follow the root font size (`--ui-scale`, set by the Text size
 * control), so layout decisions are made in rem, not px.
 */
const rootPx = () => (typeof window === "undefined" ? 16 : parseFloat(getComputedStyle(document.documentElement).fontSize) || 16);

/** The root font size in px; updates when the Text size control changes `--ui-scale`. */
export function useRootPx(): number {
  const [px, setPx] = useState(16);
  useEffect(() => {
    const read = () => setPx(rootPx());
    read();
    const mo = new MutationObserver(read);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["style", "class"] });
    return () => mo.disconnect();
  }, []);
  return px;
}

/**
 * Width of an element in rem, or null before the first measurement (server
 * render and first paint). Re-measured on resize and on a text-size change.
 */
export function useWidthRem(ref: RefObject<HTMLElement | null>): number | null {
  const root = useRootPx();
  const [px, setPx] = useState<number | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setPx(entry.contentRect.width));
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return px === null ? null : px / root;
}

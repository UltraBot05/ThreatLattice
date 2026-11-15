"use client";

import { useEffect, useState } from "react";

/**
 * Root font size in px (1rem), kept current when the Text size control
 * changes --ui-scale. A hidden 10rem probe is watched with ResizeObserver:
 * its width changes exactly when 1rem changes, so no custom event is needed.
 * For the few places that need numbers instead of CSS (Recharts SVG props,
 * width-based column hiding). Returns 16 on the server.
 */
export function useRemPx(): number {
  const [rem, setRem] = useState(16);
  useEffect(() => {
    const probe = document.createElement("span");
    probe.setAttribute("aria-hidden", "true");
    probe.style.cssText = "position:absolute;visibility:hidden;pointer-events:none;width:10rem;height:0;top:0;left:0";
    document.body.appendChild(probe);
    const read = () => setRem(probe.getBoundingClientRect().width / 10 || 16);
    read();
    const ro = new ResizeObserver(read);
    ro.observe(probe);
    return () => {
      ro.disconnect();
      probe.remove();
    };
  }, []);
  return rem;
}

"use client";

import { useEffect, useState } from "react";
import { DEFAULT_SCALE, SCALE_KEY, UI_SCALES } from "./textScale";

/**
 * Text size control: scales the whole UI (every size is rem, see
 * globals.css `html { font-size }`). Remembered per browser in
 * localStorage; app/layout.tsx applies it before first paint.
 */
function readScale(): string {
  try {
    const s = localStorage.getItem(SCALE_KEY);
    return UI_SCALES.some((x) => x.value === s) ? (s as string) : DEFAULT_SCALE;
  } catch {
    return DEFAULT_SCALE;
  }
}

export function TextSize({ className = "" }: { className?: string }) {
  const [scale, setScale] = useState<string>(DEFAULT_SCALE);
  useEffect(() => {
    const id = requestAnimationFrame(() => setScale(readScale()));
    return () => cancelAnimationFrame(id);
  }, []);

  const choose = (v: string) => {
    setScale(v);
    document.documentElement.style.setProperty("--ui-scale", v);
    try {
      localStorage.setItem(SCALE_KEY, v);
    } catch {
      /* private mode: still applies for this page */
    }
  };

  return (
    <div className={`flex items-center gap-1 ${className}`} role="group" aria-label="Text size">
      <span className="tl-mono mr-1 text-[0.625rem] text-paper-faint">TEXT</span>
      {UI_SCALES.map((s) => (
        <button
          key={s.value}
          type="button"
          aria-pressed={scale === s.value}
          onClick={() => choose(s.value)}
          className={`tl-mono h-6 min-w-6 rounded-[2px] border px-1 text-[0.625rem] transition-colors duration-150 ${
            scale === s.value ? "border-hazard text-hazard" : "border-rule text-paper-dim hover:border-rule-strong hover:text-paper"
          }`}
        >
          {s.label}
        </button>
      ))}
    </div>
  );
}

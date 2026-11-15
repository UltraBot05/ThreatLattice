"use client";

import { useRef } from "react";
import { gsap, MOTION_OK, useGSAP } from "@/components/motion/gsap";

/**
 * Landing-page diagram: the four catalogues as their node shapes, joined by
 * the three relationships. Draws itself in hop by hop when it scrolls into
 * view (DrawSVG); reduced motion shows it complete.
 */
const STAGES = [
  { x: 60, kind: "CVE", title: "Vulnerability", sub: "CVE · NVD" },
  { x: 300, kind: "CWE", title: "Weakness", sub: "CWE · MITRE" },
  { x: 540, kind: "CAPEC", title: "Attack pattern", sub: "CAPEC · MITRE" },
  { x: 780, kind: "T", title: "Technique", sub: "ATT&CK · MITRE" },
];
const LINKS = ["instance of", "exploited by", "enables"];

function Shape({ kind, x }: { kind: string; x: number }) {
  const y = 70;
  if (kind === "CVE") return <rect data-draw x={x - 26} y={y - 26} width="52" height="52" />;
  if (kind === "CWE") return <path data-draw d={`M${x} ${y - 32} L${x + 32} ${y} L${x} ${y + 32} L${x - 32} ${y}Z`} />;
  if (kind === "CAPEC") return <path data-draw d={`M${x} ${y - 30} l26 15 v30 l-26 15 l-26 -15 v-30z`} />;
  return <circle data-draw cx={x} cy={y} r="28" />;
}

export function ChainDiagram() {
  const ref = useRef<SVGSVGElement>(null);
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        const tl = gsap.timeline({ scrollTrigger: { trigger: ref.current, start: "top 80%", once: true } });
        STAGES.forEach((_, i) => {
          tl.from(`[data-stage="${i}"] [data-draw]`, { drawSVG: "0%", duration: 0.5, ease: "power2.out" });
          tl.from(`[data-stage="${i}"] text`, { autoAlpha: 0, y: 6, duration: 0.3 }, "-=0.2");
          if (i < LINKS.length) tl.from(`[data-link="${i}"]`, { drawSVG: "0%", duration: 0.35, ease: "none" });
        });
      });
    },
    { scope: ref },
  );

  return (
    <svg ref={ref} viewBox="0 0 840 160" className="h-auto w-full" role="img" aria-label="CVE, instance of CWE, exploited by CAPEC, enables ATT&CK technique">
      {LINKS.map((label, i) => (
        <g key={label}>
          <line data-link={i} x1={STAGES[i].x + 40} y1="70" x2={STAGES[i + 1].x - 40} y2="70" stroke="var(--color-hazard)" strokeWidth="1.5" />
          <text x={(STAGES[i].x + STAGES[i + 1].x) / 2} y="58" textAnchor="middle" fill="var(--color-paper-faint)" fontFamily="var(--font-mono)" fontSize="11" letterSpacing="1">
            {label.toUpperCase()}
          </text>
        </g>
      ))}
      {STAGES.map((s, i) => (
        <g key={s.kind} data-stage={i} fill="none" stroke="var(--color-paper)" strokeWidth="1.5">
          <Shape kind={s.kind} x={s.x} />
          <text x={s.x} y="126" textAnchor="middle" stroke="none" fill="var(--color-paper)" fontFamily="var(--font-sans)" fontSize="15">
            {s.title}
          </text>
          <text x={s.x} y="146" textAnchor="middle" stroke="none" fill="var(--color-paper-dim)" fontFamily="var(--font-mono)" fontSize="11">
            {s.sub}
          </text>
        </g>
      ))}
    </svg>
  );
}

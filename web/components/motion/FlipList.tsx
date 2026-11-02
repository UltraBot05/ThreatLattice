"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { Flip, gsap, prefersReducedMotion, useGSAP } from "./gsap";

/**
 * Animate reorders and filter changes instead of snapping (GSAP Flip).
 *
 *   <FlipList flipKey={`${sort}-${filters}`}>
 *     {rows.map(r => <div key={r.id} data-flip-id={r.id}>...</div>)}
 *   </FlipList>
 *
 * How: the positions of all [data-flip-id] children are recorded after every
 * commit and again right before any click/keypress (capture phase), i.e. just
 * before the state change that reorders them. When flipKey changes, Flip
 * animates from those recorded positions. No manual capture() call needed.
 * Use div rows (role="row"), not <tr>: table rows cannot be positioned.
 */
export function FlipList({
  flipKey,
  children,
  className = "",
  role,
}: {
  flipKey: string | number;
  children: ReactNode;
  className?: string;
  role?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const last = useRef<Flip.FlipState | null>(null);

  useEffect(() => {
    const record = () => {
      if (ref.current) last.current = Flip.getState(ref.current.querySelectorAll("[data-flip-id]"));
    };
    document.addEventListener("pointerdown", record, true);
    document.addEventListener("keydown", record, true);
    return () => {
      document.removeEventListener("pointerdown", record, true);
      document.removeEventListener("keydown", record, true);
    };
  }, []);

  useGSAP(
    () => {
      const el = ref.current;
      if (!el) return;
      const targets = el.querySelectorAll("[data-flip-id]");
      const next = Flip.getState(targets);
      const prev = last.current;
      last.current = next;
      if (!prev || prefersReducedMotion()) return;
      Flip.from(prev, {
        targets,
        duration: 0.45,
        ease: "power2.inOut",
        absolute: true,
        onEnter: (els) => gsap.fromTo(els, { opacity: 0 }, { opacity: 1, duration: 0.3 }),
        onLeave: (els) => gsap.to(els, { opacity: 0, duration: 0.2 }),
      });
    },
    { dependencies: [flipKey], scope: ref },
  );

  return (
    <div ref={ref} className={className} role={role}>
      {children}
    </div>
  );
}

/** Lattice mark: the four node shapes (CVE square, CWE diamond, Technique circle, CAPEC hexagon) joined by hazard links. */
export function LogoMark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" aria-hidden="true">
      <g fill="none" strokeWidth="1.2">
        <g stroke="var(--color-paper)">
          <rect x="2" y="2" width="5" height="5" />
          <path d="M15.5 1.5l3 3-3 3-3-3z" />
          <circle cx="4.5" cy="15.5" r="2.5" />
          <path d="M15.5 12.5l2.6 1.5v3l-2.6 1.5-2.6-1.5v-3z" />
        </g>
        <path d="M7 4.5h5.5M4.5 7v6M15.5 7.5v5M7 15.5h5.9" stroke="var(--color-hazard)" />
      </g>
    </svg>
  );
}

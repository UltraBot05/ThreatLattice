import { CountUp } from "@/components/motion/CountUp";

/** One ruled row of KPI cells (not separate cards). tone="hazard" for the danger number. */
export interface Kpi {
  label: string;
  value: number;
  tone?: "default" | "hazard";
  hint?: string;
}

export function KpiStrip({ items }: { items: Kpi[] }) {
  return (
    <div className="grid grid-cols-2 border-y border-rule md:grid-cols-4">
      {items.map((k, i) => (
        <div
          key={k.label}
          className={`px-3 py-3 ${i % 2 === 1 ? "border-l border-rule" : ""} ${i >= 2 ? "border-t border-rule md:border-t-0" : ""} ${i === 2 ? "md:border-l" : ""}`}
        >
          <p className="tl-label">{k.label}</p>
          <p className={`mt-1 text-2xl ${k.tone === "hazard" ? "text-hazard" : "text-paper"}`}>
            <CountUp value={k.value} />
          </p>
          {k.hint ? <p className="mt-0.5 text-[11px] text-paper-faint">{k.hint}</p> : null}
        </div>
      ))}
    </div>
  );
}

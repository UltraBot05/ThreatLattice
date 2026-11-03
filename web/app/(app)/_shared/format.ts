/** Formatting shared by Akshansh's pages (dashboard, search, CVE, spotlight, audit). */

export const fmtInt = (n: number) => n.toLocaleString("en-US");

export const fmtPct = (part: number, whole: number) =>
  whole === 0 ? "0%" : `${((part / whole) * 100).toFixed(part / whole < 0.01 ? 2 : 1)}%`;

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "2026-10-21" -> "21 Oct 2026". Dates from MySQL DATE columns are calendar dates: no time zone. */
export function fmtDate(d: string | null | undefined): string {
  if (!d) return "";
  const [y, m, day] = d.slice(0, 10).split("-");
  return `${Number(day)} ${MONTHS[Number(m) - 1]} ${y}`;
}

/** "2026-10" -> "Oct 2026" (or "Oct" when short). */
export function fmtMonth(ym: string, short = false): string {
  const [y, m] = ym.split("-");
  return short ? MONTHS[Number(m) - 1] : `${MONTHS[Number(m) - 1]} ${y}`;
}

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const STEPS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["second", 60],
  ["minute", 60],
  ["hour", 24],
  ["day", 30],
  ["month", 12],
  ["year", Infinity],
];

/** "3 minutes ago", "yesterday". */
export function fmtRelative(iso: string, now = Date.now()): string {
  let v = (new Date(iso).getTime() - now) / 1000;
  for (const [unit, size] of STEPS) {
    if (Math.abs(v) < size) return rtf.format(Math.round(v), unit);
    v /= size;
  }
  return iso;
}

/** Exact local time for tooltips: "2 Nov 2026, 23:57:26". */
export function fmtExact(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

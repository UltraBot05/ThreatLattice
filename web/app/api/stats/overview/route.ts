import type { NextRequest } from "next/server";
import { z } from "zod";
import { parseQuery, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { NO_STORE, type StatsOverview } from "@/lib/cve";
import { query, queryOne } from "@/lib/db/mysql";

/**
 * GET /api/stats/overview?year=2026 (year optional = all years)
 * -> { year, total, kevCount, bySeverity, byYear, topCwes }
 *
 * - bySeverity comes from the stored procedure sp_severity_breakdown(year)
 *   (03_routines.sql), so the dashboard and the report use the same numbers.
 * - byYear always covers every year (it is the trend chart).
 * - Year filters are date ranges, not YEAR(published_date) = ?, so
 *   idx_cve_published can be used.
 */
const schema = z.object({ year: z.coerce.number().int().min(1999).max(2100).optional() });

const TOP = 10;

// All years: count from cve_cwe alone (index only), then a correlated
// subquery averages the score for just the top 10. About 2.5x faster than
// joining every cve_cwe row to cve before grouping (1.0 s vs 2.5 s).
const TOP_CWES_ALL = `
  SELECT t.cwe_id, w.name, w.common_name, t.count,
         (SELECT ROUND(AVG(c.cvss_base_score), 2)
          FROM cve_cwe x JOIN cve c ON c.cve_id = x.cve_id
          WHERE x.cwe_id = t.cwe_id) AS avg_score
  FROM (SELECT cwe_id, COUNT(*) AS count FROM cve_cwe
        GROUP BY cwe_id ORDER BY count DESC, cwe_id LIMIT ?) t
  JOIN cwe w ON w.cwe_id = t.cwe_id
  ORDER BY t.count DESC, t.cwe_id`;

// One year: the date filter is on cve, so the join is needed anyway.
const TOP_CWES_YEAR = `
  SELECT x.cwe_id, w.name, w.common_name, COUNT(*) AS count, ROUND(AVG(c.cvss_base_score), 2) AS avg_score
  FROM cve_cwe x
  JOIN cve c ON c.cve_id = x.cve_id
  JOIN cwe w ON w.cwe_id = x.cwe_id
  WHERE c.published_date >= ? AND c.published_date < ?
  GROUP BY x.cwe_id, w.name, w.common_name
  ORDER BY count DESC, x.cwe_id
  LIMIT ?`;

export const GET = route(async (req: NextRequest) => {
  await requireUser();
  const { year } = parseQuery(req, schema);
  const range = year ? [`${year}-01-01`, `${year + 1}-01-01`] : [];
  const inYear = year ? "WHERE published_date >= ? AND published_date < ?" : "";

  const [totals, breakdown, byYear, topCwes] = await Promise.all([
    queryOne<{ total: number; kevCount: number | string }>(
      `SELECT COUNT(*) AS total, COALESCE(SUM(is_kev), 0) AS kevCount FROM cve ${inYear}`,
      range,
    ),
    // CALL returns [rows, OkPacket]; the rows are the first element.
    query<unknown>("CALL sp_severity_breakdown(?)", [year ?? null]),
    query<StatsOverview["byYear"][number]>(
      "SELECT YEAR(published_date) AS year, COUNT(*) AS count FROM cve GROUP BY YEAR(published_date) ORDER BY year",
    ),
    query<StatsOverview["topCwes"][number]>(year ? TOP_CWES_YEAR : TOP_CWES_ALL, [...range, TOP]),
  ]);

  const severityRows = breakdown[0] as { severity: StatsOverview["bySeverity"][number]["severity"]; cve_count: number; avg_score: number | null }[];
  const body: StatsOverview = {
    year: year ?? null,
    total: totals?.total ?? 0,
    kevCount: Number(totals?.kevCount ?? 0), // SUM() of a BOOLEAN comes back as DECIMAL
    bySeverity: severityRows.map((r) => ({ severity: r.severity, count: r.cve_count, avg_score: r.avg_score })),
    byYear,
    topCwes,
  };
  return Response.json(body, { headers: NO_STORE });
});

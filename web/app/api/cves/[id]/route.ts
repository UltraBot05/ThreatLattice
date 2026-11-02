import type { NextRequest } from "next/server";
import { ids, notFound, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { NO_STORE, type CveDetail } from "@/lib/cve";
import { query, queryOne } from "@/lib/db/mysql";

/**
 * GET /api/cves/CVE-2026-109618
 * -> { cve, cwes: [{id, name, common_name}], products: [{vendor, product, version}], productsTotal, events: [{slug, name, note}] }
 *
 * Products are capped at PRODUCT_LIMIT: one Cisco CVE lists 3,396 of them.
 * productsTotal is the real count, so the page can say "showing 200 of 3,396".
 */
const PRODUCT_LIMIT = 200;

type CveCols = Omit<CveDetail["cve"], "is_kev" | "kev_ransomware"> & { is_kev: number; kev_ransomware: number };

export const GET = route(async (_req: NextRequest, ctx: RouteContext<"/api/cves/[id]">) => {
  await requireUser();
  const id = ids.cve.parse((await ctx.params).id.trim().toUpperCase()); // params arrive URL-decoded

  const [cve, cwes, products, count, events] = await Promise.all([
    queryOne<CveCols>(
      `SELECT cve_id, description, published_date, last_modified_date, cvss_base_score, cvss_severity,
              cvss_version, cvss_vector, cvss_source, is_kev, kev_date_added, kev_ransomware
       FROM cve WHERE cve_id = ?`,
      [id],
    ),
    query<CveDetail["cwes"][number]>(
      `SELECT w.cwe_id AS id, w.name, w.common_name
       FROM cve_cwe x JOIN cwe w ON w.cwe_id = x.cwe_id
       WHERE x.cve_id = ?
       ORDER BY CAST(SUBSTRING(w.cwe_id, 5) AS UNSIGNED)`,
      [id],
    ),
    query<CveDetail["products"][number]>(
      `SELECT p.vendor, p.product, p.version
       FROM cve_cpe x JOIN cpe p ON p.cpe_id = x.cpe_id
       WHERE x.cve_id = ?
       ORDER BY p.vendor, p.product, p.version
       LIMIT ?`,
      [id, PRODUCT_LIMIT],
    ),
    queryOne<{ n: number }>("SELECT COUNT(*) AS n FROM cve_cpe WHERE cve_id = ?", [id]),
    query<CveDetail["events"][number]>(
      `SELECT e.slug, e.name, x.note
       FROM event_cve x JOIN security_event e ON e.event_id = x.event_id
       WHERE x.cve_id = ?
       ORDER BY e.starts_on DESC`,
      [id],
    ),
  ]);
  if (!cve) throw notFound(`${id} is not in the database.`);

  const body: CveDetail = {
    cve: { ...cve, is_kev: cve.is_kev === 1, kev_ransomware: cve.kev_ransomware === 1 },
    cwes,
    products,
    productsTotal: count?.n ?? 0,
    events,
  };
  return Response.json(body, { headers: NO_STORE });
});

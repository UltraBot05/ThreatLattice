import type { NextRequest } from "next/server";
import { z } from "zod";
import { badRequest, ids, pagination, parseQuery, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { CVE_ROW_COLUMNS, NO_STORE, withCwes, type CveDbRow } from "@/lib/cve";
import { query, queryOne } from "@/lib/db/mysql";
import { planSearch } from "@/lib/search";
import type { CveRow, Paged } from "@/lib/types";

/**
 * GET /api/cves?q=&severity=&from=&to=&kev=&cwe=&sort=&page=&pageSize=
 * -> { items: CveRow[], total, page, pageSize }
 *
 * - q: words in the description (FULLTEXT, BOOLEAN MODE, see lib/search.ts),
 *   or a CVE ID ("CVE-2024-3400") / ID prefix ("CVE-2024-34").
 * - severity: one or more of CRITICAL,HIGH,MEDIUM,LOW,NONE,UNSCORED (comma separated).
 * - from / to: published date range, YYYY-MM-DD, both ends included.
 * - kev: true = only CISA known-exploited, false = only not.
 * - cwe: CVEs linked to this CWE (CWE-79).
 * - sort: newest (default), oldest, score (highest first), relevance (default when q is given:
 *   best text match first, or for an ID search the exact ID first).
 *
 * Queries `cve` directly (not v_cve_summary, which materialises every row).
 * Only fixed SQL fragments are joined; every value goes in as a `?` param.
 */
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNSCORED"] as const;
const date = z.iso.date("expected YYYY-MM-DD");

const schema = z
  .object({
    q: z.string().max(200).optional(),
    severity: z
      .string()
      .transform((s) => [...new Set(s.toUpperCase().split(",").map((v) => v.trim()).filter(Boolean))])
      .pipe(z.array(z.enum(SEVERITIES)).min(1))
      .optional(),
    from: date.optional(),
    to: date.optional(),
    kev: z.enum(["true", "false", "1", "0"]).transform((v) => v === "true" || v === "1").optional(),
    cwe: z
      .string()
      .transform((s) => s.trim().toUpperCase())
      .pipe(ids.cwe)
      .optional(),
    sort: z.enum(["newest", "oldest", "score", "relevance"]).optional(),
    ...pagination,
  })
  .refine((v) => !v.from || !v.to || v.from <= v.to, { message: "from must not be after to", path: ["from"] });

// Whitelist: the only ORDER BY clauses that can ever be sent. cve_id breaks ties so pages never overlap.
const ORDER_BY = {
  newest: "c.published_date DESC, c.cve_id DESC",
  oldest: "c.published_date ASC, c.cve_id ASC",
  score: "c.cvss_base_score DESC, c.cve_id DESC", // DESC puts unscored (NULL) last
  relevance: "MATCH(c.description) AGAINST (? IN BOOLEAN MODE) DESC, c.cve_id DESC", // takes the search string again
  idMatch: "CHAR_LENGTH(c.cve_id), c.cve_id", // "relevance" for an ID search: the exact ID first
} as const;

export const GET = route(async (req: NextRequest) => {
  await requireUser();
  const p = parseQuery(req, schema);

  const where: string[] = [];
  const params: unknown[] = [];
  let fulltext: string | null = null;
  let idSearch = false;

  if (p.q !== undefined) {
    const plan = planSearch(p.q);
    if (plan.kind === "empty") {
      throw badRequest("Search for words of 3 or more letters (common words like 'the' or 'with' are ignored).");
    }
    if (plan.kind === "id") {
      idSearch = true;
      where.push("c.cve_id LIKE ?");
      params.push(`${plan.prefix}%`); // only letters, digits and "-": nothing to escape
    } else {
      fulltext = plan.against;
      where.push("MATCH(c.description) AGAINST (? IN BOOLEAN MODE)");
      params.push(fulltext);
    }
  }
  if (p.severity) {
    const scored = p.severity.filter((s) => s !== "UNSCORED");
    const parts: string[] = [];
    if (scored.length) {
      parts.push("c.cvss_severity IN (?)");
      params.push(scored);
    }
    if (p.severity.includes("UNSCORED")) parts.push("c.cvss_severity IS NULL");
    where.push(`(${parts.join(" OR ")})`);
  }
  if (p.from) {
    where.push("c.published_date >= ?");
    params.push(p.from);
  }
  if (p.to) {
    where.push("c.published_date <= ?");
    params.push(p.to);
  }
  if (p.kev !== undefined) {
    where.push("c.is_kev = ?");
    params.push(p.kev);
  }
  if (p.cwe) {
    where.push("EXISTS (SELECT 1 FROM cve_cwe x WHERE x.cve_id = c.cve_id AND x.cwe_id = ?)");
    params.push(p.cwe);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const relevance = fulltext ? "relevance" : idSearch ? "idMatch" : null;
  const requested = p.sort ?? relevance ?? "newest";
  if (requested === "relevance" && !relevance) throw badRequest("sort=relevance needs a search in q.");
  const sort = requested === "relevance" ? relevance! : requested;

  const pageParams = [...params, ...(sort === "relevance" ? [fulltext] : []), p.pageSize, (p.page - 1) * p.pageSize];

  const [rows, count] = await Promise.all([
    query<CveDbRow>(
      `SELECT ${CVE_ROW_COLUMNS} FROM cve c ${whereSql} ORDER BY ${ORDER_BY[sort]} LIMIT ? OFFSET ?`,
      pageParams,
    ),
    queryOne<{ total: number }>(`SELECT COUNT(*) AS total FROM cve c ${whereSql}`, params),
  ]);

  const items: CveRow[] = await withCwes(rows);
  const body: Paged<CveRow> = { items, total: count?.total ?? 0, page: p.page, pageSize: p.pageSize };
  return Response.json(body, { headers: NO_STORE });
});

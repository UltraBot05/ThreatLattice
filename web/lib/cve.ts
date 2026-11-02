import "server-only";
import { query } from "@/lib/db/mysql";
import type { CveRow, CvssSource, Severity } from "@/lib/types";

/**
 * Shared pieces of the CVE API routes (A7). Everything here queries the
 * base tables, never v_cve_summary: that view has a GROUP BY, so MySQL
 * materialises all 164k rows before any filter (3.7 s even for 8 CVEs).
 */

/** The CveRow columns of `cve`, for a FROM clause that aliases cve as `c`. */
export const CVE_ROW_COLUMNS =
  "c.cve_id, c.description, c.published_date, c.cvss_base_score, c.cvss_severity, c.cvss_source, c.is_kev";

export type CveDbRow = Omit<CveRow, "cwes" | "is_kev"> & { is_kev: number };

/** Sort CWE-79 before CWE-1021 (by number, not as text). */
export const CWE_ORDER = "CAST(SUBSTRING(cwe_id, 5) AS UNSIGNED)";

/**
 * Add `cwes: string[]` to a page of rows with ONE extra query
 * (WHERE cve_id IN (...)) instead of one query per row, or a GROUP BY join
 * over the whole result before LIMIT.
 */
export async function withCwes<R extends { cve_id: string; is_kev: number | null }>(
  rows: R[],
): Promise<(Omit<R, "is_kev"> & { is_kev: boolean; cwes: string[] })[]> {
  const byCve = new Map<string, string[]>();
  if (rows.length > 0) {
    const links = await query<{ cve_id: string; cwe_id: string }>(
      `SELECT cve_id, cwe_id FROM cve_cwe WHERE cve_id IN (?) ORDER BY cve_id, ${CWE_ORDER}`,
      [rows.map((r) => r.cve_id)],
    );
    for (const l of links) byCve.set(l.cve_id, [...(byCve.get(l.cve_id) ?? []), l.cwe_id]);
  }
  return rows.map((r) => ({ ...r, is_kev: r.is_kev === 1, cwes: byCve.get(r.cve_id) ?? [] }));
}

/** GET /api/cves/[id] */
export interface CveDetail {
  cve: {
    cve_id: string;
    description: string;
    published_date: string;
    last_modified_date: string | null;
    cvss_base_score: number | null;
    cvss_severity: Severity | null;
    cvss_version: string | null;
    cvss_vector: string | null;
    cvss_source: CvssSource | null;
    is_kev: boolean;
    kev_date_added: string | null;
    kev_ransomware: boolean;
  };
  /** name = official CWE name; common_name = everyday label (e.g. "SQL Injection") or null. */
  cwes: { id: string; name: string; common_name: string | null }[];
  /** First PRODUCT_LIMIT affected products; productsTotal says how many there are. */
  products: { vendor: string; product: string; version: string }[];
  productsTotal: number;
  events: { slug: string; name: string; note: string | null }[];
}

/** One row of /api/events/[slug]: a CveRow, but the CVE may not be in NVD yet (event_cve has no FK). */
export type EventCveRow = Omit<CveRow, "description" | "published_date" | "is_kev"> & {
  description: string | null;
  published_date: string | null;
  is_kev: boolean;
  /** false = curated ID that NVD has not published yet ("awaiting NVD data"). */
  in_nvd: boolean;
  note: string | null;
};

/** GET /api/stats/overview */
export interface StatsOverview {
  year: number | null;
  total: number;
  kevCount: number;
  /** From sp_severity_breakdown: CRITICAL..NONE, then UNSCORED. */
  bySeverity: { severity: Severity | "UNSCORED"; count: number; avg_score: number | null }[];
  /** Always all years (the trend chart), whatever ?year= says. */
  byYear: { year: number; count: number }[];
  topCwes: { cwe_id: string; name: string; common_name: string | null; count: number; avg_score: number | null }[];
}

/** One row of GET /api/admin/audit. */
export interface AuditRow {
  log_id: number;
  ts: string;
  action: "INSERT" | "UPDATE" | "DELETE" | "LOGIN" | "LOGIN_FAIL" | "ROLE_CHANGE";
  entity: string;
  entity_id: string | null;
  user_id: number | null;
  username: string | null;
  details: Record<string, unknown> | null;
}

/** Authenticated data: never stored by the browser or a proxy. */
export const NO_STORE = { "Cache-Control": "private, no-store" };

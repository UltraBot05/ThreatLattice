import type { NextRequest } from "next/server";
import { z } from "zod";
import { pagination, parseQuery, route } from "@/lib/api";
import { requireRole } from "@/lib/auth/session";
import { NO_STORE, type AuditRow } from "@/lib/cve";
import { query, queryOne } from "@/lib/db/mysql";
import type { Paged } from "@/lib/types";

/**
 * GET /api/admin/audit?action=&page=&pageSize=  (admin only)
 * -> { items: AuditRow[], total, page, pageSize }, newest first.
 *
 * Rows come from the audit triggers (04_triggers.sql: investigations, role
 * changes) and from the auth API (LOGIN, LOGIN_FAIL). username is NULL when
 * the row has no user (unknown-user LOGIN_FAIL) or the user was deleted
 * (audit_log.user_id is ON DELETE SET NULL). idx_audit_action_ts / idx_audit_ts
 * cover both orderings. ts is sent as ISO 8601 UTC, built from
 * UNIX_TIMESTAMP(), so it is exact whatever the server's time zone is.
 */
const ACTIONS = ["INSERT", "UPDATE", "DELETE", "LOGIN", "LOGIN_FAIL", "ROLE_CHANGE"] as const;

const schema = z.object({
  action: z
    .string()
    .transform((s) => s.trim().toUpperCase())
    .pipe(z.enum(ACTIONS))
    .optional(),
  ...pagination,
});

export const GET = route(async (req: NextRequest) => {
  await requireRole("admin");
  const p = parseQuery(req, schema);
  const where = p.action ? "WHERE a.action = ?" : "";
  const params = p.action ? [p.action] : [];

  const [items, count] = await Promise.all([
    query<Omit<AuditRow, "ts"> & { ts_unix: number }>(
      `SELECT a.log_id, UNIX_TIMESTAMP(a.ts) AS ts_unix, a.action, a.entity, a.entity_id, a.user_id, u.username, a.details
       FROM audit_log a LEFT JOIN app_user u ON u.user_id = a.user_id
       ${where}
       ORDER BY a.ts DESC, a.log_id DESC
       LIMIT ? OFFSET ?`,
      [...params, p.pageSize, (p.page - 1) * p.pageSize],
    ),
    queryOne<{ total: number }>(`SELECT COUNT(*) AS total FROM audit_log a ${where}`, params),
  ]);

  const rows: AuditRow[] = items.map(({ ts_unix, ...r }) => ({ ...r, ts: new Date(Number(ts_unix) * 1000).toISOString() }));
  const body: Paged<AuditRow> = { items: rows, total: count?.total ?? 0, page: p.page, pageSize: p.pageSize };
  return Response.json(body, { headers: NO_STORE });
});

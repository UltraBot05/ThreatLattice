import "server-only";
import { execute } from "@/lib/db/mysql";

/**
 * Application-side audit rows (LOGIN, LOGIN_FAIL). Investigation and role
 * changes are logged by database triggers instead (04_triggers.sql).
 * Never throws: a failed audit write must not block signing in.
 */
export async function audit(
  action: "LOGIN" | "LOGIN_FAIL" | "INSERT",
  entity: string,
  entityId: string | null,
  userId: number | null,
  details: Record<string, unknown>,
): Promise<void> {
  try {
    await execute(
      "INSERT INTO audit_log (user_id, action, entity, entity_id, details) VALUES (?, ?, ?, ?, CAST(? AS JSON))",
      [userId, action, entity, entityId ? entityId.slice(0, 40) : null, JSON.stringify(details)],
    );
  } catch (err) {
    console.error("[audit]", (err as Error).message);
  }
}

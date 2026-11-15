import "server-only";
import { z } from "zod";
import { notFound } from "@/lib/api";
import { query, queryOne } from "@/lib/db/mysql";
import { START_TYPES, type Investigation, type SessionUser } from "@/lib/types";

/**
 * Investigations (B5): a saved attack chain with a title and notes.
 * Create goes through Akshansh's sp_create_investigation (one transaction,
 * validates the user and the start node, SIGNALs readable errors); update and
 * delete are plain DML. All three fire the audit triggers (04_triggers.sql).
 * Analysts see and change only their own; admins see and change all.
 */
export const createSchema = z.object({
  title: z.string().trim().min(1, "Give it a title.").max(200, "At most 200 characters."),
  start_node_type: z.enum(START_TYPES),
  start_node_id: z.string().trim().toUpperCase().min(1).max(20),
  notes: z.string().max(20000, "Notes are limited to 20,000 characters.").optional(),
});

export const updateSchema = z
  .object({
    title: z.string().trim().min(1, "Give it a title.").max(200, "At most 200 characters.").optional(),
    notes: z.string().max(20000, "Notes are limited to 20,000 characters.").nullable().optional(),
  })
  .refine((v) => v.title !== undefined || v.notes !== undefined, { message: "Nothing to update." });

export const idParam = z.coerce.number().int().positive();

// Timestamps leave as ISO UTC (UNIX_TIMESTAMP), like the audit API, so the browser shows local time.
const COLUMNS = `
  i.investigation_id, i.user_id, u.username AS owner, i.title, i.start_node_type, i.start_node_id, i.notes,
  UNIX_TIMESTAMP(i.created_at) AS created_s, UNIX_TIMESTAMP(i.updated_at) AS updated_s`;

type Row = Omit<Investigation, "created_at" | "updated_at"> & { created_s: number; updated_s: number | null };

const toIso = (s: number) => new Date(Number(s) * 1000).toISOString();
const shape = (r: Row): Investigation => {
  const { created_s, updated_s, ...rest } = r;
  return { ...rest, created_at: toIso(created_s), updated_at: updated_s ? toIso(updated_s) : null };
};

export async function listInvestigations(user: SessionUser, all: boolean): Promise<Investigation[]> {
  const everyone = all && user.role === "admin";
  const rows = await query<Row>(
    `SELECT ${COLUMNS}
     FROM investigation i JOIN app_user u ON u.user_id = i.user_id
     ${everyone ? "" : "WHERE i.user_id = ?"}
     ORDER BY COALESCE(i.updated_at, i.created_at) DESC, i.investigation_id DESC
     LIMIT 500`,
    everyone ? [] : [user.id],
  );
  return rows.map(shape);
}

/** One investigation the user may see, or a 404 (never a 403, so ids of others' work are not revealed). */
export async function getOwned(user: SessionUser, id: number): Promise<Investigation> {
  const row = await queryOne<Row>(
    `SELECT ${COLUMNS}
     FROM investigation i JOIN app_user u ON u.user_id = i.user_id
     WHERE i.investigation_id = ? AND (i.user_id = ? OR ? = 'admin')`,
    [id, user.id, user.role],
  );
  if (!row) throw notFound("No such investigation.");
  return shape(row);
}

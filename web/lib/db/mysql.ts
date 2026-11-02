import "server-only";
import mysql, {
  type Pool,
  type PoolConnection,
  type ResultSetHeader,
  type RowDataPacket,
} from "mysql2/promise";
import { requireEnv } from "@/lib/env";

/**
 * MySQL access for route handlers (HANDOFF 4.8).
 *
 * - Connects as the least-privilege app user (MYSQL_APP_USER), never root.
 * - ALWAYS pass values as `?` params. Never build SQL by concatenating input.
 *   (We use pool.query, which escapes params client-side; it also accepts
 *   `LIMIT ?`, which mysql2's prepared `execute` does not.)
 * - DATE/TIMESTAMP come back as strings ("2026-10-21"), DECIMAL as numbers,
 *   so rows can go straight into Response.json().
 */

type Params = readonly unknown[];

const globalForPool = globalThis as unknown as { __tlMysqlPool?: Pool };

function pool(): Pool {
  if (!globalForPool.__tlMysqlPool) {
    globalForPool.__tlMysqlPool = mysql.createPool({
      host: process.env.MYSQL_HOST ?? "127.0.0.1",
      port: Number(process.env.MYSQL_PORT ?? 3307),
      database: process.env.MYSQL_DATABASE ?? "threatlattice",
      user: requireEnv("MYSQL_APP_USER"),
      password: requireEnv("MYSQL_APP_PASSWORD"),
      connectionLimit: 10,
      waitForConnections: true,
      dateStrings: true,
      decimalNumbers: true,
      supportBigNumbers: true,
      multipleStatements: false,
      charset: "utf8mb4",
    });
  }
  return globalForPool.__tlMysqlPool;
}

/** SELECT: returns the rows. */
export async function query<T = RowDataPacket>(sql: string, params: Params = []): Promise<T[]> {
  const [rows] = await pool().query(sql, params as unknown[]);
  return rows as T[];
}

/** First row or null. */
export async function queryOne<T = RowDataPacket>(sql: string, params: Params = []): Promise<T | null> {
  const rows = await query<T>(sql, params);
  return rows[0] ?? null;
}

/** INSERT / UPDATE / DELETE: returns affectedRows, insertId. */
export async function execute(sql: string, params: Params = []): Promise<ResultSetHeader> {
  const [res] = await pool().query<ResultSetHeader>(sql, params as unknown[]);
  return res;
}

export interface Tx {
  query<T = RowDataPacket>(sql: string, params?: Params): Promise<T[]>;
  execute(sql: string, params?: Params): Promise<ResultSetHeader>;
}

function bind(conn: PoolConnection): Tx {
  return {
    async query<T = RowDataPacket>(sql: string, params: Params = []) {
      const [rows] = await conn.query(sql, params as unknown[]);
      return rows as T[];
    },
    async execute(sql: string, params: Params = []) {
      const [res] = await conn.query<ResultSetHeader>(sql, params as unknown[]);
      return res;
    },
  };
}

/**
 * Run several statements as one transaction: all commit or none do.
 * Do NOT call stored procedures that START TRANSACTION themselves in here
 * (sp_create_investigation): MySQL would implicitly commit our transaction.
 */
export async function withTransaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
  const conn = await pool().getConnection();
  try {
    await conn.beginTransaction();
    const result = await fn(bind(conn));
    await conn.commit();
    return result;
  } catch (err) {
    await conn.rollback().catch(() => {});
    throw err;
  } finally {
    conn.release();
  }
}

/**
 * Several statements on ONE connection without a wrapping transaction.
 * Needed for procedures with OUT params: `CALL p(?, @out)` then `SELECT @out`
 * only works on the same session.
 */
export async function withConnection<T>(fn: (c: Tx) => Promise<T>): Promise<T> {
  const conn = await pool().getConnection();
  try {
    return await fn(bind(conn));
  } finally {
    conn.release();
  }
}

/** mysql2 error shape (errno 1644 = SIGNAL from our procedures, 3819 = CHECK failed, 1062 = duplicate key). */
export interface MysqlError extends Error {
  errno?: number;
  sqlState?: string;
  sqlMessage?: string;
}

export function isMysqlError(e: unknown): e is MysqlError {
  return typeof e === "object" && e !== null && "errno" in e && "sqlState" in e;
}

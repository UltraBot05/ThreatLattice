import "server-only";
import { connection, NextResponse, type NextRequest } from "next/server";
import { z, ZodError } from "zod";
import { isMysqlError } from "@/lib/db/mysql";

/**
 * API helpers (HANDOFF 4.8). Every route handler is wrapped in `route()`, so
 * every error leaves in one shape:
 *   { "error": { "code": "...", "message": "..." } }
 */
export type ApiErrorCode =
  | "BAD_REQUEST"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "TOO_MANY_REQUESTS"
  | "DB_ERROR";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: ApiErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export const badRequest = (m: string) => new ApiError(400, "BAD_REQUEST", m);
export const unauthorized = (m = "Sign in to continue.") => new ApiError(401, "UNAUTHORIZED", m);
export const forbidden = (m = "You do not have access to this.") => new ApiError(403, "FORBIDDEN", m);
export const notFound = (m = "Not found.") => new ApiError(404, "NOT_FOUND", m);
export const tooManyRequests = (m: string) => new ApiError(429, "TOO_MANY_REQUESTS", m);

function errorResponse(status: number, code: ApiErrorCode, message: string) {
  return NextResponse.json({ error: { code, message } }, { status });
}

export function toErrorResponse(err: unknown): NextResponse {
  if (err instanceof ApiError) return errorResponse(err.status, err.code, err.message);
  if (err instanceof ZodError) {
    const msg = err.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`).join("; ");
    return errorResponse(400, "BAD_REQUEST", msg);
  }
  if (isMysqlError(err)) {
    // 1644: SIGNAL from our procedures (UI-ready message). 3819: CHECK constraint.
    // 1062: duplicate key. 1452: FK target missing. These are the caller's fault.
    if (err.errno === 1644) return errorResponse(400, "BAD_REQUEST", err.sqlMessage ?? "Rejected by the database.");
    if (err.errno === 3819) return errorResponse(400, "BAD_REQUEST", "A value is outside the allowed range or format.");
    if (err.errno === 1062) return errorResponse(400, "BAD_REQUEST", "That value already exists.");
    if (err.errno === 1452) return errorResponse(400, "BAD_REQUEST", "A referenced record does not exist.");
    console.error("[db]", err.errno, err.sqlMessage);
    return errorResponse(500, "DB_ERROR", "The database could not complete the request.");
  }
  console.error("[api]", err);
  return errorResponse(500, "DB_ERROR", "Something went wrong on the server.");
}

type Handler<Ctx> = (req: NextRequest, ctx: Ctx) => Promise<Response>;

/**
 * Wrap a route handler so thrown errors become the standard error JSON.
 * Also marks the handler as request-time only (connection()): our API reads
 * cookies and the databases, so it must never be prerendered at build time.
 */
export function route<Ctx = unknown>(handler: Handler<Ctx>): Handler<Ctx> {
  return async (req, ctx) => {
    await connection();
    try {
      return await handler(req, ctx);
    } catch (err) {
      return toErrorResponse(err);
    }
  };
}

/** Validate the query string with a zod schema (use z.coerce for numbers). */
export function parseQuery<S extends z.ZodType>(req: NextRequest, schema: S): z.infer<S> {
  const obj: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => {
    if (v !== "") obj[k] = v;
  });
  return schema.parse(obj);
}

/** Validate a JSON body with a zod schema. */
export async function parseBody<S extends z.ZodType>(req: NextRequest, schema: S): Promise<z.infer<S>> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw badRequest("Body must be valid JSON.");
  }
  return schema.parse(body);
}

/** Common validators, shared so every route checks ids the same way the DB does. */
export const ids = {
  cve: z.string().regex(/^CVE-\d{4}-\d+$/, "expected CVE-YYYY-NNNN"),
  cwe: z.string().regex(/^CWE-\d+$/, "expected CWE-N"),
  capec: z.string().regex(/^CAPEC-\d+$/, "expected CAPEC-N"),
  technique: z.string().regex(/^T\d{4}(\.\d{3})?$/, "expected T1234 or T1234.001"),
};

export const pagination = {
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
};

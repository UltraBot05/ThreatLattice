import { ApiError, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";

/**
 * GET /api/auth/me: { user } for the signed-in, active user, or { user: null }.
 * (200 either way: "not signed in" is a normal state for the sidebar.)
 */
export const GET = route(async () => {
  try {
    return Response.json({ user: await requireUser() }, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return Response.json({ user: null }, { headers: { "Cache-Control": "no-store" } });
    }
    throw err;
  }
});

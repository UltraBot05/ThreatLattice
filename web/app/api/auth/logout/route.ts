import { route } from "@/lib/api";
import { destroySession } from "@/lib/auth/session";

/** POST /api/auth/logout: clears the session cookie. */
export const POST = route(async () => {
  await destroySession();
  return Response.json({ ok: true });
});

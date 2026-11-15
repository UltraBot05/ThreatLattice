import { route } from "@/lib/api";
import { requireRole } from "@/lib/auth/session";
import { listUsers } from "@/lib/users";

/** GET /api/admin/users (admin only) -> { items: AdminUser[] }. No password hashes. */
export const GET = route(async () => {
  await requireRole("admin");
  return Response.json({ items: await listUsers() }, { headers: { "Cache-Control": "private, no-store" } });
});

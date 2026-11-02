import type { NextRequest } from "next/server";
import { z } from "zod";
import { notFound, route } from "@/lib/api";
import { requireUser } from "@/lib/auth/session";
import { NO_STORE, withCwes, type EventCveRow } from "@/lib/cve";
import { query, queryOne } from "@/lib/db/mysql";

/**
 * GET /api/events/black-october-2026
 * -> { event: {slug, name, starts_on, ends_on, summary}, cves: EventCveRow[] }
 *
 * event_cve has no FK to cve (an event is curated from the news, often
 * before NVD publishes the CVE), so this LEFT JOINs cve: a CVE that is not
 * loaded yet still appears, with in_nvd = false and NULL score fields.
 * Sorted by score, highest first, unscored and missing last.
 */
const slugSchema = z.string().max(64).regex(/^[a-z0-9-]+$/, "expected a slug like black-october-2026");

type EventDbRow = Omit<EventCveRow, "is_kev" | "in_nvd" | "cwes"> & { is_kev: number | null; in_nvd: number };

export const GET = route(async (_req: NextRequest, ctx: RouteContext<"/api/events/[slug]">) => {
  await requireUser();
  const slug = slugSchema.parse((await ctx.params).slug);

  const event = await queryOne<{ event_id: number; slug: string; name: string; starts_on: string; ends_on: string; summary: string | null }>(
    "SELECT event_id, slug, name, starts_on, ends_on, summary FROM security_event WHERE slug = ?",
    [slug],
  );
  if (!event) throw notFound(`No event called ${slug}.`);

  const rows = await query<EventDbRow>(
    `SELECT x.cve_id, c.description, c.published_date, c.cvss_base_score, c.cvss_severity, c.cvss_source,
            c.is_kev, c.cve_id IS NOT NULL AS in_nvd, x.note
     FROM event_cve x LEFT JOIN cve c ON c.cve_id = x.cve_id
     WHERE x.event_id = ?
     ORDER BY c.cvss_base_score IS NULL, c.cvss_base_score DESC, x.cve_id`,
    [event.event_id],
  );
  const cves: EventCveRow[] = (await withCwes(rows)).map((r) => ({ ...r, in_nvd: r.in_nvd === 1 }));

  const { slug: s, name, starts_on, ends_on, summary } = event; // event_id stays internal
  return Response.json({ event: { slug: s, name, starts_on, ends_on, summary }, cves }, { headers: NO_STORE });
});

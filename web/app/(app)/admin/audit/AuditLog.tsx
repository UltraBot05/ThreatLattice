"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/Button";
import { DataTable } from "@/components/ui/DataTable";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { PageHeader } from "@/components/ui/Text";
import { useApi } from "@/lib/client/api";
import type { AuditRow } from "@/lib/cve";
import type { Paged } from "@/lib/types";
import { fmtExact, fmtInt, fmtRelative } from "../../_shared/format";

/**
 * /admin/audit: who did what, newest first. Rows come from the database
 * triggers (investigations, role changes) and from sign-in (LOGIN,
 * LOGIN_FAIL). Filter chips and the page are kept in the URL.
 */
const ACTIONS = [
  { value: "", label: "All" },
  { value: "LOGIN", label: "Sign-in" },
  { value: "LOGIN_FAIL", label: "Failed sign-in" },
  { value: "INSERT", label: "Created" },
  { value: "UPDATE", label: "Updated" },
  { value: "DELETE", label: "Deleted" },
  { value: "ROLE_CHANGE", label: "Role change" },
] as const;
const PAGE_SIZE = 50;

export function AuditLog() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const action = params.get("action") ?? "";
  const page = Math.max(1, Number(params.get("page")) || 1);

  const qs = new URLSearchParams({ pageSize: String(PAGE_SIZE), page: String(page) });
  if (action) qs.set("action", action);
  const { data, error, loading, reload } = useApi<Paged<AuditRow>>(`/api/admin/audit?${qs.toString()}`);
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  // Relative times ("3 minutes ago") tick once a minute.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(t);
  }, []);

  const go = (next: { action?: string; page?: number }) => {
    const p = new URLSearchParams();
    const a = next.action ?? action;
    const pg = next.page ?? (next.action !== undefined ? 1 : page);
    if (a) p.set("action", a);
    if (pg > 1) p.set("page", String(pg));
    const s = p.toString();
    router.replace(s ? `${pathname}?${s}` : pathname, { scroll: false });
  };

  return (
    <div>
      <PageHeader
        crumb="ADMIN / AUDIT LOG"
        title="Audit log"
        subtitle="Every sign-in, failed sign-in, investigation change and role change, newest first."
      />

      <div className="flex flex-wrap items-center justify-between gap-3 pb-3">
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by action">
          {ACTIONS.map((a) => {
            const on = action === a.value;
            return (
              <button
                key={a.value || "all"}
                type="button"
                aria-pressed={on}
                onClick={() => go({ action: a.value })}
                className={`h-7 rounded-[2px] border px-2.5 text-xs transition-colors duration-150 ${
                  on ? "border-paper bg-ink-3 text-paper" : "border-rule text-paper-dim hover:border-rule-strong hover:text-paper"
                }`}
              >
                {a.label}
              </button>
            );
          })}
        </div>
        <p className="tl-mono text-xs text-paper-dim" aria-live="polite">
          {data ? `${fmtInt(data.total)} ${data.total === 1 ? "entry" : "entries"}` : "Loading"}
        </p>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : (
        <div className={`transition-opacity duration-150 ${loading && data ? "opacity-60" : ""}`}>
          <DataTable
            caption="Audit log"
            loading={!data}
            rows={data?.items ?? []}
            rowId={(r) => String(r.log_id)}
            flipKey={(data?.items ?? []).map((r) => r.log_id).join(",")}
            empty={
              <EmptyState
                message={action ? "No entries for this action yet." : "Nothing has been logged yet. Sign-ins and investigation changes appear here."}
                action={
                  action ? (
                    <Button size="sm" onClick={() => go({ action: "" })}>
                      Show all actions
                    </Button>
                  ) : undefined
                }
              />
            }
            columns={[
              {
                key: "ts",
                header: "When",
                width: "150px",
                render: (r) => (
                  <time dateTime={r.ts} title={fmtExact(r.ts)} className="tl-mono text-xs text-paper-dim">
                    {fmtRelative(r.ts, now)}
                  </time>
                ),
              },
              {
                key: "action",
                header: "Action",
                width: "112px",
                render: (r) => <span className={`tl-mono text-xs ${r.action === "LOGIN_FAIL" ? "text-hazard" : "text-paper"}`}>{r.action}</span>,
              },
              {
                key: "user",
                header: "User",
                width: "130px",
                render: (r) =>
                  r.username ? (
                    <span className="block truncate text-[13px]">{r.username}</span>
                  ) : (
                    <span className="text-xs text-paper-faint">{r.action === "LOGIN_FAIL" ? "unknown user" : "none"}</span>
                  ),
              },
              {
                key: "entity",
                header: "Record",
                width: "170px",
                render: (r) => (
                  <span className="tl-mono text-xs">
                    {r.entity}
                    {r.entity_id ? <span className="text-paper-dim"> #{r.entity_id}</span> : null}
                  </span>
                ),
              },
              { key: "details", header: "Details", width: "minmax(220px,1fr)", render: (r) => <Details d={r.details} /> },
            ]}
          />
        </div>
      )}

      {data && data.total > PAGE_SIZE ? (
        <nav className="flex items-center justify-between gap-3 border-t border-rule pt-3" aria-label="Pages">
          <Button size="sm" disabled={page <= 1} onClick={() => go({ page: page - 1 })}>
            Previous
          </Button>
          <span className="tl-mono text-xs text-paper-dim">
            Page {fmtInt(page)} of {fmtInt(pages)}
          </span>
          <Button size="sm" disabled={page >= pages} onClick={() => go({ page: page + 1 })}>
            Next
          </Button>
        </nav>
      ) : null}
    </div>
  );
}

/** details JSON as "key value" pairs; before/after (UPDATE) shows only the fields that changed. */
function Details({ d }: { d: Record<string, unknown> | null }) {
  if (!d || Object.keys(d).length === 0) return <span className="text-xs text-paper-faint">none</span>;
  const before = d.before as Record<string, unknown> | undefined;
  const after = d.after as Record<string, unknown> | undefined;
  const pairs: [string, string][] =
    before && after
      ? Object.keys(after)
          .filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k]))
          .map((k) => [k, `${String(before[k] ?? "empty")} to ${String(after[k] ?? "empty")}`])
      : Object.entries(d).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)]);
  const text = pairs.map(([k, v]) => `${k}: ${v}`).join("; ");
  return (
    <span className="block truncate text-xs text-paper-dim" title={text}>
      {pairs.length === 0
        ? "no visible change"
        : pairs.map(([k, v], i) => (
            <span key={k}>
              {i > 0 ? "; " : ""}
              <span className="text-paper-faint">{k}</span> {v}
            </span>
          ))}
    </span>
  );
}

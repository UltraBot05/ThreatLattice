"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { IdText, PageHeader } from "@/components/ui/Text";
import { useApi } from "@/lib/client/api";
import type { Investigation } from "@/lib/types";
import { fmtExact, fmtRelative } from "../_shared/format";

/** /investigations : saved chains. Admins can switch to everyone's. */
export function InvestigationList() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const scope = params.get("scope") === "all" ? "all" : "mine";
  const me = useApi<{ user: { role: string } | null }>("/api/auth/me");
  const isAdmin = me.data?.user?.role === "admin";
  const { data, error, loading, reload } = useApi<{ items: Investigation[] }>(`/api/investigations?scope=${scope}`);

  const columns: Column<Investigation>[] = [
    { key: "title", header: "Title", render: (r) => <span className="block truncate text-paper" title={r.title}>{r.title}</span> },
    {
      key: "start",
      header: "Starts from",
      width: "11rem",
      render: (r) => (
        <span className="flex items-baseline gap-2">
          <span className="tl-mono text-[0.625rem] text-paper-faint">{r.start_node_type}</span>
          <IdText id={r.start_node_id} />
        </span>
      ),
    },
    ...(scope === "all" ? [{ key: "owner", header: "Owner", width: "8rem", render: (r: Investigation) => <span className="tl-mono text-[0.75rem]">{r.owner}</span> }] : []),
    {
      key: "updated",
      header: "Last change",
      width: "9rem",
      align: "right",
      render: (r) => {
        const t = r.updated_at ?? r.created_at;
        return <span className="tl-mono text-[0.75rem] text-paper-dim" title={fmtExact(t)}>{fmtRelative(t)}</span>;
      },
    },
  ];

  return (
    <>
      <PageHeader
        crumb="INVESTIGATIONS"
        title={<>Saved <i className="text-paper-dim">chains</i></>}
        subtitle="Attack chains you saved from the explorer, with your notes. Every create, edit and delete is written to the audit log by a database trigger."
        actions={
          isAdmin ? (
            <div className="flex gap-2" role="group" aria-label="Whose investigations">
              {(["mine", "all"] as const).map((s) => (
                <Button
                  key={s}
                  size="sm"
                  variant={scope === s ? "primary" : "secondary"}
                  aria-pressed={scope === s}
                  onClick={() => router.replace(s === "mine" ? pathname : `${pathname}?scope=all`, { scroll: false })}
                >
                  {s === "mine" ? "Mine" : "Everyone"}
                </Button>
              ))}
            </div>
          ) : null
        }
      />
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : (
        <DataTable
          caption="Saved investigations"
          columns={columns}
          rows={data?.items ?? []}
          rowId={(r) => String(r.investigation_id)}
          rowHref={(r) => `/investigations/${r.investigation_id}`}
          loading={loading && !data}
          flipKey={scope}
          empty={
            <EmptyState
              label="NOTHING SAVED YET"
              message="Open any attack chain and choose Save investigation to keep it here with your notes."
              action={<Button size="sm" href="/explore">Explore a chain</Button>}
            />
          }
        />
      )}
    </>
  );
}

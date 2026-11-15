"use client";

import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { ErrorState } from "@/components/ui/States";
import { PageHeader } from "@/components/ui/Text";
import { api, useApi } from "@/lib/client/api";
import type { Role } from "@/lib/types";
import { fmtExact, fmtRelative } from "../../_shared/format";

/**
 * /admin/users : change roles and activate/deactivate accounts.
 * Role changes are logged by the trg_user_au trigger (ROLE_CHANGE),
 * activation changes by the API (UPDATE). Both show in the Audit log.
 */
interface AdminUser {
  user_id: number;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
  investigations: number;
}

export function UserAdmin() {
  const { data, error, loading, reload } = useApi<{ items: AdminUser[] }>("/api/admin/users");
  const me = useApi<{ user: { id: number } | null }>("/api/auth/me");
  const [busy, setBusy] = useState<number | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const patch = async (u: AdminUser, body: { role?: Role; is_active?: boolean }) => {
    setBusy(u.user_id);
    setActionErr(null);
    try {
      await api(`/api/admin/users/${u.user_id}`, { method: "PATCH", body: JSON.stringify(body) });
      reload();
    } catch (e) {
      setActionErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const columns: Column<AdminUser>[] = [
    {
      key: "user",
      header: "User",
      render: (u) => (
        <span className="block min-w-0">
          <span className={`tl-mono block ${u.is_active ? "text-paper" : "text-paper-faint line-through"}`}>
            {u.username}
            {u.user_id === me.data?.user?.id ? <span className="ml-2 text-[0.625rem] text-paper-faint">(you)</span> : null}
          </span>
          <span className="block truncate text-[0.75rem] text-paper-dim">{u.email}</span>
        </span>
      ),
    },
    {
      key: "role",
      header: "Role",
      width: "7rem",
      render: (u) => <span className={`tl-mono text-[0.75rem] uppercase ${u.role === "admin" ? "text-hazard" : "text-paper"}`}>{u.role}</span>,
    },
    { key: "inv", header: "Saved", width: "5rem", align: "right", render: (u) => <span className="tl-mono">{u.investigations}</span> },
    {
      key: "login",
      header: "Last sign-in",
      width: "9rem",
      render: (u) =>
        u.last_login_at ? (
          <span className="tl-mono text-[0.75rem] text-paper-dim" title={fmtExact(u.last_login_at)}>{fmtRelative(u.last_login_at)}</span>
        ) : (
          <span className="text-[0.75rem] text-paper-faint">never</span>
        ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "17rem",
      align: "right",
      render: (u) => (
        <span className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" disabled={busy === u.user_id} onClick={() => patch(u, { role: u.role === "admin" ? "analyst" : "admin" })}>
            {u.role === "admin" ? "Make analyst" : "Make admin"}
          </Button>
          <Button size="sm" variant="ghost" disabled={busy === u.user_id} onClick={() => patch(u, { is_active: !u.is_active })}>
            {u.is_active ? "Deactivate" : "Reactivate"}
          </Button>
        </span>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        crumb="ADMIN / USERS"
        title={<>People and <i className="text-paper-dim">roles</i></>}
        subtitle="Analysts explore and save chains; admins also manage people and read the audit log. A deactivated account is signed out at its next request. You can't remove your own admin access, and the last admin can't be removed."
      />
      {actionErr ? <div className="mb-4"><ErrorState message={actionErr} /></div> : null}
      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : (
        <DataTable caption="Users" columns={columns} rows={data?.items ?? []} rowId={(u) => String(u.user_id)} loading={loading && !data} />
      )}
    </>
  );
}

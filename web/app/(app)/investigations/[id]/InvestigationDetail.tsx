"use client";

import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { Declassify } from "@/components/motion/Declassify";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/Field";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { IdText, Panel } from "@/components/ui/Text";
import { api, useApi } from "@/lib/client/api";
import type { Investigation } from "@/lib/types";
import { fmtExact, fmtRelative } from "../../_shared/format";

/** /investigations/[id] : rename, write notes, delete. Each action is one DML statement (UPDATE / DELETE) that the audit triggers record. */
export function InvestigationDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { data, error, reload } = useApi<{ investigation: Investigation }>(`/api/investigations/${encodeURIComponent(id)}`);
  const inv = data?.investigation;

  const [title, setTitle] = useState<string | null>(null);
  const [notes, setNotes] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const t = title ?? inv?.title ?? "";
  const n = notes ?? inv?.notes ?? "";
  const dirty = !!inv && (t !== inv.title || n !== (inv.notes ?? ""));

  const save = async () => {
    if (!inv) return;
    setSaving(true);
    setSaveErr(null);
    try {
      const body: Record<string, string> = {};
      if (t !== inv.title) body.title = t;
      if (n !== (inv.notes ?? "")) body.notes = n;
      await api(`/api/investigations/${inv.investigation_id}`, { method: "PATCH", body: JSON.stringify(body) });
      setTitle(null);
      setNotes(null);
      setSaved("Saved");
      reload();
    } catch (e) {
      setSaveErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!inv) return;
    try {
      await api(`/api/investigations/${inv.investigation_id}`, { method: "DELETE" });
      router.replace("/investigations");
    } catch (e) {
      setSaveErr((e as Error).message);
    }
  };

  if (error) {
    return /no such investigation/i.test(error) ? (
      <EmptyState label="NOT FOUND" message="This investigation does not exist, or it is not yours." action={<Button size="sm" href="/investigations">All investigations</Button>} />
    ) : (
      <ErrorState message={error} onRetry={reload} />
    );
  }

  const chainHref = inv?.start_node_type === "CVE" ? `/explore/${inv.start_node_id}` : null;

  return (
    <div>
      <header className="mb-6 border-b border-rule pb-4">
        <p className="tl-label">THREATLATTICE / INVESTIGATIONS / {id}</p>
        <Declassify loading={!inv} lines={2} className="mt-2">
          {inv ? (
            <div className="flex flex-wrap items-end justify-between gap-4">
              <h1 className="font-display text-[2.25rem] leading-tight text-paper">{inv.title}</h1>
              {chainHref ? <Button variant="primary" href={chainHref}>Open chain</Button> : null}
            </div>
          ) : (
            <div />
          )}
        </Declassify>
      </header>

      {inv ? (
        <div className="grid grid-cols-1 gap-10 lg:grid-cols-12">
          <aside className="flex flex-col gap-4 lg:col-span-4">
            <Panel label="Starts from">
              <p className="flex items-baseline gap-2">
                <span className="tl-mono text-[0.6875rem] text-paper-faint">{inv.start_node_type}</span>
                <IdText id={inv.start_node_id} href={chainHref ?? undefined} className="text-lg" />
              </p>
            </Panel>
            <Panel label="Record">
              <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-[0.8125rem]">
                <dt className="tl-label self-center">Owner</dt>
                <dd className="tl-mono">{inv.owner}</dd>
                <dt className="tl-label self-center">Created</dt>
                <dd title={fmtExact(inv.created_at)}>{fmtRelative(inv.created_at)}</dd>
                <dt className="tl-label self-center">Changed</dt>
                <dd title={inv.updated_at ? fmtExact(inv.updated_at) : undefined}>{inv.updated_at ? fmtRelative(inv.updated_at) : "never"}</dd>
              </dl>
            </Panel>
            <Panel label="Danger zone">
              {confirmDelete ? (
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="primary" onClick={remove}>Delete for good</Button>
                  <Button size="sm" variant="ghost" onClick={() => setConfirmDelete(false)}>Keep it</Button>
                </div>
              ) : (
                <Button size="sm" onClick={() => setConfirmDelete(true)}>Delete investigation</Button>
              )}
            </Panel>
          </aside>

          <section className="flex flex-col gap-4 lg:col-span-8">
            <Field label="Title" htmlFor="inv-title">
              <Input id="inv-title" value={t} maxLength={200} onChange={(e) => { setTitle(e.target.value); setSaved(null); }} />
            </Field>
            <Field label="Notes" htmlFor="inv-notes">
              <textarea
                id="inv-notes"
                value={n}
                maxLength={20000}
                rows={14}
                onChange={(e) => { setNotes(e.target.value); setSaved(null); }}
                placeholder="What you found, which techniques matter for your systems, what to patch first."
                className="w-full rounded-[2px] border border-rule bg-ink-2 px-3 py-2 text-[0.875rem] leading-6 text-paper placeholder:text-paper-faint hover:border-rule-strong focus-visible:border-hazard"
              />
            </Field>
            {saveErr ? <ErrorState message={saveErr} /> : null}
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={save} disabled={!dirty || saving || !t.trim()}>
                {saving ? "Saving" : "Save changes"}
              </Button>
              <span className="tl-mono text-[0.75rem] text-paper-faint" aria-live="polite">
                {dirty ? "Unsaved changes" : saved ?? ""}
              </span>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}

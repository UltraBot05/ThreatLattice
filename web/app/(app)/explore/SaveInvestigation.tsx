"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/Button";
import { Field, Input } from "@/components/ui/Field";
import { api } from "@/lib/client/api";
import type { Investigation } from "@/lib/types";

/** "Save investigation" from the explorer: title + optional notes -> POST /api/investigations (sp_create_investigation). */
export function SaveInvestigation({ cveId, summary }: { cveId: string; summary: string }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState(`Attack chain for ${cveId}`);
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<Investigation | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return setErr("Give it a title.");
    setBusy(true);
    setErr(null);
    try {
      const { investigation } = await api<{ investigation: Investigation }>("/api/investigations", {
        method: "POST",
        body: JSON.stringify({ title, start_node_type: "CVE", start_node_id: cveId, notes: notes || `${summary}` }),
      });
      setSaved(investigation);
      setOpen(false);
    } catch (e2) {
      setErr((e2 as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (saved) {
    return (
      <p className="tl-mono flex items-center gap-2 text-[0.75rem] text-paper-dim" aria-live="polite">
        SAVED
        <Link href={`/investigations/${saved.investigation_id}`} className="text-paper underline underline-offset-4 hover:text-hazard">
          Open investigation
        </Link>
      </p>
    );
  }

  return (
    <div className="relative">
      <Button size="sm" variant="secondary" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        Save investigation
      </Button>
      {open ? (
        <form
          onSubmit={submit}
          noValidate
          className="absolute right-0 top-full z-20 mt-2 flex w-[22rem] flex-col gap-3 border border-rule-strong bg-ink-2 p-4"
        >
          <Field label="Title" htmlFor="save-title" error={err ?? undefined}>
            <Input id="save-title" value={title} maxLength={200} autoFocus onChange={(e) => setTitle(e.target.value)} />
          </Field>
          <Field label="Notes (optional)" htmlFor="save-notes">
            <textarea
              id="save-notes"
              value={notes}
              rows={4}
              maxLength={20000}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={summary}
              className="w-full rounded-[2px] border border-rule bg-ink px-3 py-2 text-[0.8125rem] text-paper placeholder:text-paper-faint focus-visible:border-hazard"
            />
          </Field>
          <div className="flex gap-2">
            <Button type="submit" size="sm" variant="primary" disabled={busy}>{busy ? "Saving" : "Save"}</Button>
            <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
          </div>
        </form>
      ) : null}
    </div>
  );
}

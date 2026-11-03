"use client";

import { MagnifyingGlass } from "@phosphor-icons/react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { DataTable } from "@/components/ui/DataTable";
import { Input, Select } from "@/components/ui/Field";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { KevTag, SeverityTag } from "@/components/ui/Tags";
import { IdText, PageHeader } from "@/components/ui/Text";
import { useApi } from "@/lib/client/api";
import { planSearch } from "@/lib/search";
import type { CveRow, Paged } from "@/lib/types";
import { fmtDate, fmtInt } from "../_shared/format";

/**
 * /search: full-text and filter search over every CVE.
 * - The URL is the state (/search?q=php&severity=CRITICAL&kev=true): shareable,
 *   Back works, and the sidebar's "Jump to CVE" lands here with ?q=.
 * - Typing is debounced 300 ms before it reaches the URL (and the API).
 * - "/" focuses the search box on this page (instead of the sidebar jump box).
 * - Results keep the previous page on screen while the next one loads, so the
 *   table can animate from old rows to new ones (FlipList) instead of blanking.
 */
const SEVERITIES = [
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "MEDIUM", label: "Medium" },
  { value: "LOW", label: "Low" },
  { value: "NONE", label: "None" },
  { value: "UNSCORED", label: "Not scored" },
] as const;
const SORTS = [
  { value: "", label: "Best match" },
  { value: "newest", label: "Newest" },
  { value: "oldest", label: "Oldest" },
  { value: "score", label: "Highest score" },
];
const PAGE_SIZE = 25;
const FILTER_KEYS = ["q", "severity", "from", "to", "kev", "cwe", "sort", "page"] as const;

function isTyping(t: EventTarget | null) {
  const el = t as HTMLElement | null;
  return !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
}

export function SearchView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const inputRef = useRef<HTMLInputElement>(null);

  const get = (k: (typeof FILTER_KEYS)[number]) => params.get(k) ?? "";
  const q = get("q");
  const severity = get("severity").split(",").filter(Boolean);
  const sort = get("sort");
  const page = Math.max(1, Number(get("page")) || 1);

  /** Write filters to the URL. Any filter change goes back to page 1. */
  const update = (patch: Partial<Record<(typeof FILTER_KEYS)[number], string>>) => {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("page" in patch)) next.delete("page");
    const qs = next.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  };

  // Debounced text box -> ?q=
  const [text, setText] = useState(q);
  const [lastQ, setLastQ] = useState(q);
  if (q !== lastQ) {
    // URL changed from outside (Back, sidebar jump): follow it.
    setLastQ(q);
    setText(q);
  }
  useEffect(() => {
    if (text.trim() === q) return;
    const t = setTimeout(() => update({ q: text.trim() }), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- update() reads the latest params itself
  }, [text]);

  // "/" focuses the search box. Capture phase + stopPropagation so the
  // sidebar's own "/" (focus Jump to CVE) does not also fire on this page.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
      e.preventDefault();
      e.stopPropagation();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, []);

  // Words that the full-text index cannot use (1-2 letters, "the", "with") are
  // checked here with the same rules as the API, so we never send a request
  // that can only fail.
  const plan = q ? planSearch(q) : null;
  const unsearchable = plan?.kind === "empty";
  const apiUrl = useMemo(() => {
    const p = new URLSearchParams();
    for (const k of FILTER_KEYS) {
      const v = params.get(k);
      if (v && !(k === "q" && unsearchable)) p.set(k, v);
    }
    p.set("pageSize", String(PAGE_SIZE));
    return `/api/cves?${p.toString()}`;
  }, [params, unsearchable]);

  const { data, error, loading, reload } = useApi<Paged<CveRow>>(apiUrl);
  const rows = data?.items ?? [];
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const anyFilter = FILTER_KEYS.some((k) => k !== "page" && k !== "sort" && params.get(k));

  const toggleSeverity = (v: string) => {
    const set = new Set(severity);
    if (set.has(v)) set.delete(v);
    else set.add(v);
    update({ severity: SEVERITIES.map((s) => s.value).filter((s) => set.has(s)).join(",") });
  };

  const countText = !data
    ? "Searching"
    : `${fmtInt(data.total)} ${data.total === 1 ? "CVE matches" : "CVEs match"}${anyFilter ? "" : " (all CVEs, newest first)"}`;

  return (
    <div>
      <PageHeader crumb="SEARCH" title="Search" subtitle="Find CVEs by words in their description or by ID, then narrow by severity, date, KEV and weakness." />

      {/* Command bar */}
      {/* The focus ring sits on the whole bar (2px hazard, offset 2px), not on the bare input inside it
          (outline-none! because the global :focus-visible rule is unlayered and beats utilities). */}
      <div className="flex h-12 items-center gap-3 border border-rule-strong bg-ink-2 px-3 focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-hazard">
        <MagnifyingGlass size={18} weight="regular" aria-hidden="true" className="shrink-0 text-paper-dim" />
        <input
          ref={inputRef}
          type="search"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="php remote code execution, or CVE-2024-3400"
          aria-label="Search CVEs"
          className="h-full min-w-0 flex-1 bg-transparent text-[15px] text-paper outline-none placeholder:text-paper-faint focus-visible:outline-none!"
          autoComplete="off"
          spellCheck={false}
        />
        <kbd className="tl-mono hidden border border-rule px-1.5 text-[11px] text-paper-faint sm:inline">/</kbd>
      </div>
      {unsearchable ? (
        <p className="mt-2 text-xs text-paper-dim" role="status">
          Words under 3 letters and common words like &quot;the&quot; are not indexed. Add a longer word to search.
        </p>
      ) : null}

      {/* Filter row */}
      <div className="mt-4 flex flex-wrap items-end gap-x-6 gap-y-3 border-b border-rule pb-4">
        <fieldset className="flex flex-col gap-1.5">
          <legend className="tl-label mb-1.5">Severity</legend>
          <div className="flex flex-wrap gap-1">
            {SEVERITIES.map((s) => {
              const on = severity.includes(s.value);
              return (
                <button
                  key={s.value}
                  type="button"
                  aria-pressed={on}
                  onClick={() => toggleSeverity(s.value)}
                  className={`h-7 rounded-[2px] border px-2.5 text-xs transition-colors duration-150 ${
                    on ? "border-paper bg-ink-3 text-paper" : "border-rule text-paper-dim hover:border-rule-strong hover:text-paper"
                  }`}
                >
                  {s.label}
                </button>
              );
            })}
          </div>
        </fieldset>

        <div className="flex items-end gap-2">
          <label className="flex flex-col gap-1.5">
            <span className="tl-label">Published from</span>
            <Input type="date" value={get("from")} onChange={(e) => update({ from: e.target.value })} className="w-[150px] tl-mono" />
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="tl-label">to</span>
            <Input type="date" value={get("to")} onChange={(e) => update({ to: e.target.value })} className="w-[150px] tl-mono" />
          </label>
        </div>

        <CweFilter value={get("cwe")} onChange={(v) => update({ cwe: v })} />

        <label className="flex h-9 cursor-pointer items-center gap-2 text-[13px] text-paper-dim hover:text-paper">
          <input
            type="checkbox"
            checked={get("kev") === "true"}
            onChange={(e) => update({ kev: e.target.checked ? "true" : "" })}
            className="h-4 w-4 accent-[var(--color-hazard)]"
          />
          Known exploited only
        </label>

        <label className="ml-auto flex flex-col gap-1.5">
          <span className="tl-label">Sort</span>
          <Select value={sort} onChange={(e) => update({ sort: e.target.value })} className="w-[150px]">
            {SORTS.filter((o) => o.value !== "" || (q && !unsearchable)).map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </label>
      </div>

      {/* Result count (announced) + paging */}
      <div className="flex items-center justify-between gap-3 py-3">
        <p className="tl-mono text-xs text-paper-dim" aria-live="polite">
          {countText}
        </p>
        {anyFilter ? (
          <Button size="sm" variant="ghost" onClick={() => router.replace(pathname, { scroll: false })}>
            Clear filters
          </Button>
        ) : null}
      </div>

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : (
        <div className={`transition-opacity duration-150 ${loading && data ? "opacity-60" : ""}`}>
          <DataTable
            caption="Search results"
            loading={!data}
            rows={rows}
            rowId={(r) => r.cve_id}
            rowHref={(r) => `/cve/${r.cve_id}`}
            flipKey={rows.map((r) => r.cve_id).join(",")}
            empty={
              <EmptyState
                message="No CVEs match these filters."
                action={
                  <Button size="sm" onClick={() => router.replace(pathname, { scroll: false })}>
                    Clear filters
                  </Button>
                }
              />
            }
            columns={[
              { key: "id", header: "CVE", width: "140px", render: (r) => <IdText id={r.cve_id} className="text-paper" /> },
              { key: "sev", header: "Severity", width: "92px", render: (r) => <SeverityTag severity={r.cvss_severity} score={r.cvss_base_score} /> },
              {
                key: "date",
                header: "Published",
                width: "104px",
                render: (r) => <span className="tl-mono text-xs text-paper-dim">{fmtDate(r.published_date)}</span>,
              },
              { key: "kev", header: "KEV", width: "48px", render: (r) => (r.is_kev ? <KevTag compact /> : null) },
              {
                key: "cwe",
                header: "CWE",
                width: "96px",
                render: (r) => (
                  <span className="tl-mono text-xs text-paper-dim" title={r.cwes.join(", ")}>
                    {r.cwes[0] ?? <span className="text-paper-faint">none</span>}
                    {r.cwes.length > 1 ? <span className="text-paper-faint"> +{r.cwes.length - 1}</span> : null}
                  </span>
                ),
              },
              {
                key: "desc",
                header: "Description",
                width: "minmax(160px,1fr)",
                render: (r) => (
                  <span className="block truncate text-paper-dim" title={r.description}>
                    {r.description}
                  </span>
                ),
              },
            ]}
          />
        </div>
      )}

      {data && data.total > PAGE_SIZE ? (
        <nav className="flex items-center justify-between gap-3 border-t border-rule pt-3" aria-label="Pages">
          <Button size="sm" disabled={page <= 1} onClick={() => update({ page: String(page - 1) })}>
            Previous
          </Button>
          <span className="tl-mono text-xs text-paper-dim">
            Page {fmtInt(page)} of {fmtInt(pages)}
          </span>
          <Button size="sm" disabled={page >= pages} onClick={() => update({ page: String(page + 1) })}>
            Next
          </Button>
        </nav>
      ) : null}
    </div>
  );
}

/** CWE filter: applied on Enter or blur, only when it looks like CWE-<number>. */
function CweFilter({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [draft, setDraft] = useState(value);
  const [last, setLast] = useState(value);
  if (value !== last) {
    setLast(value);
    setDraft(value);
  }
  const clean = draft.trim().toUpperCase().replace(/^(\d+)$/, "CWE-$1");
  const valid = clean === "" || /^CWE-\d+$/.test(clean);
  const apply = () => {
    if (valid && clean !== value) onChange(clean);
  };
  return (
    <label className="flex flex-col gap-1.5">
      <span className="tl-label">Weakness</span>
      <Input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={apply}
        onKeyDown={(e) => e.key === "Enter" && apply()}
        placeholder="CWE-79"
        aria-invalid={!valid}
        aria-describedby={valid ? undefined : "cwe-hint"}
        className="tl-mono w-[120px]"
      />
      {!valid ? (
        <span id="cwe-hint" className="text-[11px] text-hazard">
          Use CWE-number
        </span>
      ) : null}
    </label>
  );
}

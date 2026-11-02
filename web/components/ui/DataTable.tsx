"use client";

import { useRouter } from "next/navigation";
import type { KeyboardEvent, ReactNode } from "react";
import { Declassify } from "@/components/motion/Declassify";
import { FlipList } from "@/components/motion/FlipList";
import { EmptyState } from "./States";

/**
 * Dense data table built from div rows with ARIA table roles, so rows can
 * animate with Flip. Keyboard: Tab into the table, Up/Down move between rows,
 * Enter opens the row (rowHref or onRowClick).
 * Pass flipKey (e.g. `${sort}-${filters}`) to animate reorders with Flip.
 */
export interface Column<T> {
  key: string;
  header: string;
  /** CSS grid track, e.g. "160px" or "minmax(0,1fr)". */
  width?: string;
  align?: "left" | "right";
  render: (row: T) => ReactNode;
}

export function DataTable<T>({
  columns,
  rows,
  rowId,
  rowHref,
  onRowClick,
  loading = false,
  empty,
  flipKey,
  caption,
}: {
  columns: Column<T>[];
  rows: T[];
  rowId: (row: T) => string;
  rowHref?: (row: T) => string;
  onRowClick?: (row: T) => void;
  loading?: boolean;
  empty?: ReactNode;
  flipKey?: string | number;
  caption?: string;
}) {
  const router = useRouter();
  const template = columns.map((c) => c.width ?? "minmax(0,1fr)").join(" ");
  const interactive = Boolean(rowHref || onRowClick);

  const open = (row: T) => {
    if (onRowClick) onRowClick(row);
    else if (rowHref) router.push(rowHref(row));
  };

  const onKey = (e: KeyboardEvent<HTMLDivElement>, row: T) => {
    const el = e.currentTarget;
    if (e.key === "Enter") open(row);
    if (e.key === "ArrowDown") (el.nextElementSibling as HTMLElement | null)?.focus();
    if (e.key === "ArrowUp") (el.previousElementSibling as HTMLElement | null)?.focus();
    if (e.key === "ArrowDown" || e.key === "ArrowUp") e.preventDefault();
  };

  const body = rows.map((row) => (
    <div
      key={rowId(row)}
      data-flip-id={rowId(row)}
      role="row"
      tabIndex={interactive ? 0 : -1}
      onClick={interactive ? () => open(row) : undefined}
      onKeyDown={interactive ? (e) => onKey(e, row) : undefined}
      className={`grid min-h-9 items-center gap-3 border-b border-rule px-1 py-1.5 text-[13px] ${
        interactive ? "cursor-pointer hover:bg-ink-3 focus-visible:bg-ink-3" : ""
      }`}
      style={{ gridTemplateColumns: template }}
    >
      {columns.map((c) => (
        <div key={c.key} role="cell" className={`min-w-0 ${c.align === "right" ? "text-right" : ""}`}>
          {c.render(row)}
        </div>
      ))}
    </div>
  ));

  return (
    <div role="table" aria-label={caption} aria-busy={loading} className="w-full overflow-x-auto">
      <div role="rowgroup">
        <div
          role="row"
          className="grid gap-3 border-b border-rule px-1 pb-1.5"
          style={{ gridTemplateColumns: template }}
        >
          {columns.map((c) => (
            <div key={c.key} role="columnheader" className={`tl-label ${c.align === "right" ? "text-right" : ""}`}>
              {c.header}
            </div>
          ))}
        </div>
      </div>
      <Declassify loading={loading} lines={Math.max(3, Math.min(rows.length || 6, 10))} className="pt-2">
        {rows.length === 0 ? (
          <div className="pt-1">{empty ?? <EmptyState message="Nothing to show yet." />}</div>
        ) : flipKey !== undefined ? (
          <FlipList flipKey={flipKey} role="rowgroup">
            {body}
          </FlipList>
        ) : (
          <div role="rowgroup">
            {body}
          </div>
        )}
      </Declassify>
    </div>
  );
}

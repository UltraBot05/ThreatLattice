"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  FileText,
  Fire,
  FolderSimple,
  Graph,
  List,
  MagnifyingGlass,
  SignOut,
  SquaresFour,
  Users,
  X,
  type Icon,
} from "@phosphor-icons/react";
import { LogoMark } from "./Logo";

/**
 * App navigation (HANDOFF 4.10 "Sidebar").
 * >= 1024px: 196px rail with labels. 768-1023px: 56px icon rail.
 * < 768px: top bar + slide-down menu.
 * Shortcuts: "/" focuses Jump to CVE; "g" then d/s/e/i/b jumps to a page.
 */
interface NavItem {
  href: string;
  label: string;
  icon: Icon;
  keys?: string;
  live?: boolean;
  admin?: boolean;
}

const GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Analyze",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: SquaresFour, keys: "G D" },
      { href: "/search", label: "Search", icon: MagnifyingGlass, keys: "G S" },
      { href: "/explore", label: "Explore chain", icon: Graph, keys: "G E" },
    ],
  },
  { label: "Work", items: [{ href: "/investigations", label: "Investigations", icon: FolderSimple, keys: "G I" }] },
  {
    label: "Intel",
    items: [{ href: "/spotlight/black-october-2026", label: "Black October", icon: Fire, keys: "G B", live: true }],
  },
  {
    label: "Admin",
    items: [
      { href: "/admin/users", label: "Users", icon: Users, admin: true },
      { href: "/admin/audit", label: "Audit log", icon: FileText, admin: true },
    ],
  },
];

const JUMP: Record<string, string> = {
  d: "/dashboard",
  s: "/search",
  e: "/explore",
  i: "/investigations",
  b: "/spotlight/black-october-2026",
};

type Me = { id: number; username: string; role: "analyst" | "admin" } | null;

function isTyping(t: EventTarget | null) {
  const el = t as HTMLElement | null;
  return !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
}

function daysAgo(date: string | null): string {
  if (!date) return "NO DATA LOADED";
  const d = Math.floor((Date.now() - new Date(`${date}T00:00:00Z`).getTime()) / 86_400_000);
  return d <= 0 ? "DATA AS OF TODAY" : `DATA AS OF ${d}D AGO`;
}

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const jumpRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [me, setMe] = useState<Me>(null);
  const [asOf, setAsOf] = useState<string | null | undefined>(undefined);

  useEffect(() => {
    fetch("/api/auth/me")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => setMe(d?.user ?? null))
      .catch(() => setMe(null));
    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => setAsOf(d?.dataAsOf ?? null))
      .catch(() => setAsOf(null));
  }, []);

  useEffect(() => setOpen(false), [pathname]);

  useEffect(() => {
    let gAt = 0;
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
      if (e.key === "/") {
        e.preventDefault();
        jumpRef.current?.focus();
        return;
      }
      if (e.key === "g") {
        gAt = Date.now();
        return;
      }
      if (Date.now() - gAt < 1000 && JUMP[e.key]) {
        router.push(JUMP[e.key]);
        gAt = 0;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [router]);

  const onJump = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const q = jumpRef.current?.value.trim() ?? "";
    if (!q) return;
    const id = q.toUpperCase();
    router.push(/^CVE-\d{4}-\d+$/.test(id) ? `/cve/${id}` : `/search?q=${encodeURIComponent(q)}`);
    if (jumpRef.current) jumpRef.current.value = "";
  };

  const signOut = async () => {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    router.push("/login");
  };

  const groups = GROUPS.map((g) => ({ ...g, items: g.items.filter((i) => !i.admin || me?.role === "admin") })).filter(
    (g) => g.items.length > 0,
  );

  const nav = (compact: boolean) => (
    <nav aria-label="Main" className="flex flex-col">
      {groups.map((g) => (
        <div key={g.label}>
          <p className={`tl-label px-[18px] pb-1.5 pt-3.5 text-[10px] tracking-[0.1em] text-paper-faint ${compact ? "lg:block hidden" : ""}`}>
            {g.label}
          </p>
          {g.items.map((item) => {
            const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
            const I = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                title={item.label}
                className={`mx-2 my-px flex items-center gap-2.5 rounded-[2px] px-2.5 py-[7px] text-[13px] transition-colors duration-150 ${
                  active
                    ? "bg-ink-3 text-paper shadow-[inset_2px_0_0_var(--color-hazard)]"
                    : "text-paper-dim hover:bg-ink-2 hover:text-paper"
                } ${compact ? "justify-center lg:justify-start" : ""}`}
              >
                <I size={16} weight="regular" aria-hidden="true" className="shrink-0" />
                <span className={compact ? "hidden lg:inline" : ""}>{item.label}</span>
                {item.live ? (
                  <span aria-label="live" className={`tl-pulse ml-auto h-1.5 w-1.5 rounded-full bg-hazard ${compact ? "hidden lg:block" : ""}`} />
                ) : item.keys ? (
                  <span className={`tl-mono ml-auto text-[10px] text-paper-faint ${compact ? "hidden lg:inline" : ""}`}>{item.keys}</span>
                ) : null}
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );

  const jump = (compact: boolean) => (
    <form onSubmit={onJump} role="search" className={`mx-3 mb-1 ${compact ? "hidden lg:block" : ""}`}>
      <label className="flex items-center gap-2 rounded-[2px] border border-rule px-2 py-1.5 text-xs text-paper-faint focus-within:border-hazard">
        <MagnifyingGlass size={14} aria-hidden="true" />
        <input
          ref={jumpRef}
          aria-label="Jump to CVE or search"
          placeholder="Jump to CVE"
          className="w-full bg-transparent text-paper outline-none placeholder:text-paper-faint focus-visible:outline-none"
        />
        <kbd className="tl-mono border border-rule-strong px-1 text-[10px] text-paper-faint">/</kbd>
      </label>
    </form>
  );

  const footer = (compact: boolean) => (
    <div className={`mt-auto border-t border-rule px-4 py-3 ${compact ? "hidden lg:block" : ""}`}>
      <p className="tl-mono flex items-center gap-1.5 text-[10px] text-paper-faint">
        <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-sev-low" />
        {asOf === undefined ? "CHECKING DATA" : daysAgo(asOf)}
      </p>
      {me ? (
        <div className="mt-2.5 flex items-center gap-2">
          <span className="tl-mono flex h-[26px] w-[26px] items-center justify-center border border-rule-strong text-[11px]">
            {me.username.slice(0, 2).toUpperCase()}
          </span>
          <span className="min-w-0 text-xs leading-tight">
            <span className="block truncate">{me.username}</span>
            <span className="tl-mono text-[10px] uppercase text-paper-dim">{me.role}</span>
          </span>
          <button onClick={signOut} aria-label="Sign out" className="ml-auto text-paper-faint hover:text-paper">
            <SignOut size={16} />
          </button>
        </div>
      ) : (
        <Link href="/login" className="mt-2.5 block text-xs text-paper-dim hover:text-paper">
          Sign in
        </Link>
      )}
    </div>
  );

  const brand = (compact: boolean) => (
    <Link href="/" className={`flex items-center gap-2.5 px-[18px] pb-3.5 pt-4 ${compact ? "justify-center lg:justify-start px-0 lg:px-[18px]" : ""}`}>
      <LogoMark />
      <span className={`font-display text-[21px] leading-none ${compact ? "hidden lg:inline" : ""}`}>ThreatLattice</span>
    </Link>
  );

  return (
    <>
      {/* tablet + desktop rail */}
      <aside className="sticky top-0 hidden h-dvh w-14 shrink-0 flex-col border-r border-rule bg-rail md:flex lg:w-[196px]">
        {brand(true)}
        {jump(true)}
        <div className="min-h-0 flex-1 overflow-y-auto">{nav(true)}</div>
        {footer(true)}
      </aside>

      {/* phone top bar */}
      <div className="sticky top-0 z-40 flex h-12 items-center justify-between border-b border-rule bg-rail px-4 md:hidden">
        <Link href="/" className="flex items-center gap-2">
          <LogoMark size={18} />
          <span className="font-display text-lg leading-none">ThreatLattice</span>
        </Link>
        <button aria-label={open ? "Close menu" : "Open menu"} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          {open ? <X size={20} /> : <List size={20} />}
        </button>
      </div>
      {open ? (
        <div className="fixed inset-x-0 bottom-0 top-12 z-30 flex flex-col overflow-y-auto bg-rail md:hidden">
          <div className="pt-3">{jump(false)}</div>
          {nav(false)}
          {footer(false)}
        </div>
      ) : null}
    </>
  );
}

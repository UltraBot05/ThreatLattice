import { Suspense, type ReactNode } from "react";
import { Sidebar } from "./Sidebar";

/**
 * Sidebar + main column. Content max 1320px, 24px gutters (16px on phones).
 * Sidebar reads usePathname(), which Next 16 (Cache Components) only allows
 * inside <Suspense> on dynamic [param] routes (/cve/[id], /explore/[cveId]);
 * without it `next build` fails. The fallback is an empty rail/top bar of
 * the same size, so nothing shifts when the sidebar streams in.
 */
function SidebarFallback() {
  return (
    <>
      <div aria-hidden="true" className="sticky top-0 hidden h-dvh w-14 shrink-0 border-r border-rule bg-rail md:block lg:w-[196px]" />
      <div aria-hidden="true" className="sticky top-0 z-40 h-12 border-b border-rule bg-rail md:hidden" />
    </>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      <Suspense fallback={<SidebarFallback />}>
        <Sidebar />
      </Suspense>
      <main id="main" className="min-w-0 flex-1">
        <div className="mx-auto w-full max-w-[1320px] px-4 py-5 sm:px-6 sm:py-6">{children}</div>
      </main>
    </div>
  );
}

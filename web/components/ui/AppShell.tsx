import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";

/** Sidebar + main column. Content max 1320px, 24px gutters (16px on phones). */
export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col md:flex-row">
      <Sidebar />
      <main id="main" className="min-w-0 flex-1">
        <div className="mx-auto w-full max-w-[1320px] px-4 py-5 sm:px-6 sm:py-6">{children}</div>
      </main>
    </div>
  );
}

import type { Metadata } from "next";
import { Suspense } from "react";
import { DashboardView } from "./DashboardView";

export const metadata: Metadata = { title: "Dashboard" };

// Client view: it reads ?year= with useSearchParams, so it sits in a Suspense boundary.
export default function DashboardPage() {
  return (
    <Suspense>
      <DashboardView />
    </Suspense>
  );
}

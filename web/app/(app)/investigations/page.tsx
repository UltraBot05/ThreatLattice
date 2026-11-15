import type { Metadata } from "next";
import { Suspense } from "react";
import { InvestigationList } from "./InvestigationList";

export const metadata: Metadata = { title: "Investigations" };

export default function InvestigationsPage() {
  return (
    <Suspense>
      <InvestigationList />
    </Suspense>
  );
}

import type { Metadata } from "next";
import { Suspense } from "react";
import { InvestigationDetail } from "./InvestigationDetail";

export const metadata: Metadata = { title: "Investigation" };

export default function InvestigationPage() {
  return (
    <Suspense>
      <InvestigationDetail />
    </Suspense>
  );
}

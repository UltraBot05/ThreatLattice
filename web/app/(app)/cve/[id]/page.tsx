import type { Metadata } from "next";
import { Suspense } from "react";
import { CveDossier } from "./CveDossier";

export const metadata: Metadata = { title: "CVE" };

// Client view: reads the id with useParams and loads /api/cves/[id], so it sits in a Suspense boundary.
export default function CvePage() {
  return (
    <Suspense>
      <CveDossier />
    </Suspense>
  );
}

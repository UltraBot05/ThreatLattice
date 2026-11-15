import type { Metadata } from "next";
import { Suspense } from "react";
import { ExploreView } from "./ExploreView";

export const metadata: Metadata = { title: "Explore chain" };

// Client view reads the id (useParams) and ?depth (useSearchParams), so it sits in Suspense.
export default function ExplorePage() {
  return (
    <Suspense>
      <ExploreView />
    </Suspense>
  );
}

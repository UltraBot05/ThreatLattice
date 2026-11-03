import type { Metadata } from "next";
import { Suspense } from "react";
import { SearchView } from "./SearchView";

export const metadata: Metadata = { title: "Search" };

// Client view: filters live in the URL (useSearchParams), so it sits in a Suspense boundary.
export default function SearchPage() {
  return (
    <Suspense>
      <SearchView />
    </Suspense>
  );
}

import type { Metadata } from "next";
import { ExploreHome } from "./ExploreHome";

export const metadata: Metadata = { title: "Explore chain" };

export default function ExploreIndexPage() {
  return <ExploreHome />;
}

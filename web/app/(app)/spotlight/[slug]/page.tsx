import type { Metadata } from "next";
import { Suspense } from "react";
import { SmoothScroll } from "@/components/motion/SmoothScroll";
import { Spotlight } from "./Spotlight";

export const metadata: Metadata = { title: "Spotlight" };

// Lenis is on for this page only (HANDOFF 4.10). The view reads the slug with useParams, so it sits in Suspense.
export default function SpotlightPage() {
  return (
    <SmoothScroll>
      <Suspense>
        <Spotlight />
      </Suspense>
    </SmoothScroll>
  );
}

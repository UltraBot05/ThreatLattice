import type { Metadata } from "next";
import { Suspense } from "react";
import { AuditLog } from "./AuditLog";

export const metadata: Metadata = { title: "Audit log" };

// Admin only: proxy.ts sends analysts to /dashboard, and /api/admin/audit checks the role again.
export default function AuditPage() {
  return (
    <Suspense>
      <AuditLog />
    </Suspense>
  );
}

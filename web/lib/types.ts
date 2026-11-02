/** Shapes shared by API routes and pages (HANDOFF 4.9). */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
export type CvssSource = "NVD" | "CNA" | "ADP";
export type Role = "analyst" | "admin";

export interface CveRow {
  cve_id: string;
  description: string;
  published_date: string;
  cvss_base_score: number | null;
  cvss_severity: Severity | null;
  cvss_source: CvssSource | null;
  is_kev: boolean | 0 | 1;
  cwes: string[];
}

export interface SessionUser {
  id: number;
  username: string;
  role: Role;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface ApiErrorBody {
  error: { code: string; message: string };
}

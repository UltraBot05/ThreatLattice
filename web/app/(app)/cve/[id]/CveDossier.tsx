"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/Button";
import { DataTable } from "@/components/ui/DataTable";
import { EmptyState, ErrorState } from "@/components/ui/States";
import { KevTag, SeverityTag, SourceTag } from "@/components/ui/Tags";
import { IdText, Panel } from "@/components/ui/Text";
import { Declassify } from "@/components/motion/Declassify";
import { DecodeText } from "@/components/motion/DecodeText";
import { useApi } from "@/lib/client/api";
import type { CveDetail } from "@/lib/cve";
import { fmtDate, fmtInt } from "../../_shared/format";

/**
 * /cve/[id]: one CVE as a dossier.
 * Left column = the file's cover sheet (ID, severity, KEV, dates, vector,
 * the one primary action). Right column = the body (description, weaknesses,
 * affected products, events).
 */
export function CveDossier() {
  const { id: raw } = useParams<{ id: string }>();
  const id = decodeURIComponent(raw).toUpperCase();
  const { data, error, reload } = useApi<CveDetail>(`/api/cves/${encodeURIComponent(id)}`);
  const notFound = error && /not in the database/i.test(error); // the API's 404 message (app/api/cves/[id])

  if (notFound) {
    return (
      <div>
        <Crumb id={id} />
        <EmptyState
          label="NOT FOUND"
          message={`${id} is not in the database. It may be outside 2024 to 2026, rejected by NVD, or not published yet.`}
          action={
            <Button size="sm" href={`/search?q=${encodeURIComponent(id)}`}>
              Search CVEs
            </Button>
          }
        />
      </div>
    );
  }
  if (error) {
    return (
      <div>
        <Crumb id={id} />
        <ErrorState message={error} onRetry={reload} />
      </div>
    );
  }

  const c = data?.cve;
  return (
    <div>
      <Crumb id={id} />
      <div className="grid grid-cols-1 gap-8 border-b border-rule pb-8 lg:grid-cols-12">
        {/* Cover sheet */}
        <aside className="lg:col-span-4 lg:border-r lg:border-rule lg:pr-8">
          <h1 className="tl-mono whitespace-nowrap text-[26px] leading-tight text-paper xl:text-[30px]">
            <DecodeText text={id} />
          </h1>
          <Declassify loading={!c} lines={6} className="mt-4">
            {c ? (
              <div className="flex flex-col gap-5">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                  <span className="text-base">
                    <SeverityTag severity={c.cvss_severity} score={c.cvss_base_score} />
                  </span>
                  {c.is_kev ? <KevTag /> : null}
                </div>
                <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-[13px]">
                  <Row label="Published" value={fmtDate(c.published_date)} />
                  <Row label="Modified" value={fmtDate(c.last_modified_date)} />
                  {c.is_kev ? <Row label="KEV since" value={fmtDate(c.kev_date_added)} /> : null}
                  {c.is_kev ? <Row label="Ransomware" value={c.kev_ransomware ? "Known use" : "Not known"} hazard={c.kev_ransomware} /> : null}
                  <Row label="Scored by" value={c.cvss_source ? <SourceTag source={c.cvss_source} /> : "Not scored yet"} />
                  {c.cvss_version ? <Row label="CVSS" value={`v${c.cvss_version}`} /> : null}
                </dl>
                {c.cvss_vector ? (
                  <div>
                    <p className="tl-label">Vector</p>
                    <p className="tl-mono mt-1 break-all text-xs text-paper-dim">{c.cvss_vector}</p>
                  </div>
                ) : null}
                <Button variant="primary" href={`/explore/${c.cve_id}`} className="self-start">
                  Explore chain
                </Button>
              </div>
            ) : (
              <span />
            )}
          </Declassify>
        </aside>

        {/* Body */}
        <div className="flex min-w-0 flex-col gap-8 lg:col-span-8">
          <Declassify loading={!c} lines={5}>
            {c ? <p className="max-w-[72ch] text-base leading-7 text-paper">{c.description}</p> : <span />}
          </Declassify>

          <Panel index={1} label="Weaknesses">
            <Declassify loading={!data} lines={2}>
              {data && data.cwes.length === 0 ? (
                <p className="text-[13px] text-paper-dim">NVD has not linked a weakness (CWE) to this CVE yet.</p>
              ) : (
                <ul className="flex flex-col">
                  {(data?.cwes ?? []).map((w) => (
                    <li key={w.id} className="grid grid-cols-[96px_1fr] items-baseline gap-3 border-b border-rule py-2 text-[13px] last:border-b-0">
                      <IdText id={w.id} href={`/search?cwe=${w.id}`} />
                      <span className="min-w-0">
                        <span className="text-paper">{w.common_name ?? w.name}</span>
                        {w.common_name ? <span className="block text-xs text-paper-faint">{w.name}</span> : null}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Declassify>
          </Panel>

          <Panel
            index={2}
            label="Affected products"
            actions={
              data && data.productsTotal > data.products.length ? (
                <span className="tl-mono text-[11px] text-paper-faint">
                  Showing {fmtInt(data.products.length)} of {fmtInt(data.productsTotal)}
                </span>
              ) : null
            }
          >
            <DataTable
              caption="Affected products"
              loading={!data}
              rows={data?.products ?? []}
              rowId={(p) => `${p.vendor}|${p.product}|${p.version}`}
              empty={<EmptyState label="NO PRODUCTS" message="NVD lists no vulnerable product configurations for this CVE." />}
              columns={[
                { key: "v", header: "Vendor", width: "minmax(0,1fr)", render: (p) => <span className="tl-mono text-xs">{p.vendor}</span> },
                { key: "p", header: "Product", width: "minmax(0,1.4fr)", render: (p) => <span className="tl-mono text-xs">{p.product}</span> },
                {
                  key: "ver",
                  header: "Version",
                  width: "120px",
                  render: (p) => (
                    <span
                      className="tl-mono text-xs text-paper-dim"
                      title={p.version === "*" ? "All versions (or a version range)" : p.version === "-" ? "Not applicable (CPE '-')" : undefined}
                    >
                      {p.version === "*" ? "any" : p.version === "-" ? "n/a" : p.version}
                    </span>
                  ),
                },
              ]}
            />
          </Panel>

          {data && data.events.length > 0 ? (
            <Panel index={3} label="In the news">
              <ul className="flex flex-col">
                {data.events.map((e) => (
                  <li key={e.slug} className="border-b border-rule py-2 text-[13px] last:border-b-0">
                    <Link href={`/spotlight/${e.slug}`} className="text-paper underline-offset-4 hover:text-hazard hover:underline">
                      {e.name}
                    </Link>
                    {e.note ? <span className="block text-xs text-paper-dim">{e.note}</span> : null}
                  </li>
                ))}
              </ul>
            </Panel>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function Crumb({ id }: { id: string }) {
  return <p className="tl-label mb-4">THREATLATTICE / CVE / {id}</p>;
}

function Row({ label, value, hazard = false }: { label: string; value: ReactNode; hazard?: boolean }) {
  return (
    <>
      <dt className="tl-label pt-0.5">{label}</dt>
      <dd className={`tl-mono text-[13px] ${hazard ? "text-hazard" : "text-paper"}`}>{value}</dd>
    </>
  );
}

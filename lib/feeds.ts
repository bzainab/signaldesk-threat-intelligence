import type { Intelligence, Vulnerability } from "./intelligence.ts";

type Fetcher = typeof fetch;
const KEV =
  "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";

async function json(url: string, fetcher: Fetcher, signal?: AbortSignal): Promise<any> {
  const timeout = AbortSignal.timeout(12000);
  const response = await fetcher(url, {
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    cache: "no-cache",
  });
  if (!response.ok) throw new Error(`Source returned HTTP ${response.status}`);
  return response.json();
}

export async function loadIntelligence(
  snapshotUrl: string,
  fetcher: Fetcher = fetch,
): Promise<Intelligence> {
  const base: Intelligence = await json(snapshotUrl, fetcher);
  if (!Array.isArray(base.vulnerabilities) || !Array.isArray(base.groups)) {
    throw new Error("Invalid reference data");
  }
  try {
    const kev = await json(KEV, fetcher);
    if (!Array.isArray(kev.vulnerabilities) || !kev.vulnerabilities.length) {
      throw new Error("Invalid KEV feed");
    }
    const sorted = kev.vulnerabilities.sort(
      (a: any, b: any) => b.dateAdded.localeCompare(a.dateAdded) || b.cveID.localeCompare(a.cveID),
    );
    const scores = new Map<string, any>();
    const errors: string[] = [];
    await Promise.all(
      [0, 80, 160].map(async (offset) => {
        const ids = sorted
          .slice(offset, offset + 80)
          .map((r: any) => r.cveID)
          .join(",");
        if (!ids) return;
        try {
          const result = await json(
            `https://api.first.org/data/v1/epss?cve=${ids}&limit=100`,
            fetcher,
          );
          if (!Array.isArray(result.data)) throw new Error("Invalid EPSS feed");
          result.data.forEach((r: any) => {
            if (
              Number.isFinite(Number(r.epss)) &&
              r.epss !== null &&
              r.epss !== "" &&
              Number(r.epss) >= 0 &&
              Number(r.epss) <= 1
            ) {
              scores.set(r.cve, r);
            }
          });
        } catch {
          errors.push("EPSS enrichment incomplete. Missing scores remain unknown.");
        }
      }),
    );
    const vulnerabilities: Vulnerability[] = sorted
      .filter((r: any) => /^CVE-\d{4}-\d{4,}$/.test(r.cveID))
      .map((r: any) => {
        const e = scores.get(r.cveID);
        return {
          id: r.cveID,
          title: r.vulnerabilityName,
          vendor: r.vendorProject,
          product: r.product,
          description: r.shortDescription,
          added: r.dateAdded,
          due: r.dueDate,
          ransomware: r.knownRansomwareCampaignUse === "Known",
          action: r.requiredAction,
          notes: r.notes || "",
          cwes: r.cwes || [],
          epss: e ? Number(e.epss) : null,
          percentile: e ? Number(e.percentile) : null,
          epssDate: e?.date ?? null,
        };
      });
    return {
      ...base,
      vulnerabilities,
      catalogDate: kev.dateReleased,
      mode: "live",
      liveAt: new Date().toISOString(),
      sources: base.sources.map((s) => ({
        ...s,
        records:
          s.name === "CISA KEV"
            ? vulnerabilities.length
            : s.name === "FIRST EPSS"
              ? scores.size
              : s.records,
      })),
      errors: [...new Set(errors)],
    };
  } catch {
    return {
      ...base,
      mode: "snapshot",
      errors: [
        ...base.errors,
        "Live collection is unavailable. Showing the dated reference snapshot.",
      ],
    };
  }
}

export async function loadCvss(id: string, signal?: AbortSignal, fetcher: Fetcher = fetch) {
  if (!/^CVE-\d{4}-\d{4,8}$/.test(id)) throw new Error("Invalid CVE identifier");
  const record = await json(`https://cveawg.mitre.org/api/cve/${id}`, fetcher, signal);
  const containers = [record.containers?.cna, ...(record.containers?.adp || [])].filter(Boolean);
  const metrics = containers.flatMap((c: any) =>
    (c.metrics || []).flatMap((m: any) =>
      ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
        .filter((k) => m[k])
        .map((k) => ({
          ...m[k],
          provider: c.providerMetadata?.shortName || "CVE contributor",
        })),
    ),
  );
  return { id, metrics, source: `https://www.cve.org/CVERecord?id=${id}` };
}

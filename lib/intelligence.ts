export type Vulnerability = {
  id: string;
  title: string;
  vendor: string;
  product: string;
  description: string;
  added: string;
  due: string;
  ransomware: boolean;
  action: string;
  notes: string;
  cwes: string[];
  epss: number | null;
  percentile: number | null;
  epssDate: string | null;
};
export type Technique = {
  id: string;
  name: string;
  tactics: string[];
  url: string;
};
export type Group = {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  url: string;
  modified: string;
  techniques: Technique[];
};
export type Intelligence = {
  collectedAt: string;
  catalogDate: string;
  vulnerabilities: Vulnerability[];
  groups: Group[];
  sources: { name: string; url: string; records: number }[];
  errors: string[];
  mode?: string;
  liveAt?: string;
};

// Analyst triage labels, not CVSS severity or evidence of compromise in an organisation.
export function priority(v: Vulnerability): "Elevated" | "High" | "Review" {
  if (v.ransomware || (v.epss !== null && v.epss >= 0.5)) return "Elevated";
  if (v.epss !== null && v.epss >= 0.1) return "High";
  return "Review";
}
export function filterRecords(rows: Vulnerability[], q: string, vendor: string, level: string) {
  const words = q.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return rows.filter(
    (v) =>
      (vendor === "all" || v.vendor === vendor) &&
      (level === "all" || priority(v) === level) &&
      words.every((w) =>
        `${v.id} ${v.title} ${v.vendor} ${v.product} ${v.description} ${v.cwes.join(" ")}`
          .toLowerCase()
          .includes(w),
      ),
  );
}
export function csvCell(value: unknown) {
  let s = String(value ?? "");
  if (/^[\s]*[=+@-]/.test(s)) s = "'" + s;
  return '"' + s.replaceAll('"', '""') + '"';
}
export function toCsv(rows: Vulnerability[]) {
  return [
    ["CVE", "Vendor", "Product", "Added", "Ransomware", "EPSS", "EPSS date", "Triage priority"],
    ...rows.map((v) => [
      v.id,
      v.vendor,
      v.product,
      v.added,
      v.ransomware ? "Known" : "Unknown",
      v.epss ?? "",
      v.epssDate ?? "",
      priority(v),
    ]),
  ]
    .map((r) => r.map(csvCell).join(","))
    .join("\r\n");
}

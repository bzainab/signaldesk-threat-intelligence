import { loadIntelligence, loadCvss } from "@/lib/feeds";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpRight,
  Database,
  Search,
  Shield,
  RefreshCw,
  Radio,
  ChevronLeft,
  ChevronRight,
  FileText,
  GitBranch,
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import {
  type Intelligence,
  type Vulnerability,
  type Group,
  filterRecords,
  priority,
  toCsv,
} from "@/lib/intelligence";
const fmt = (n: number) => n.toLocaleString("en-GB");
const date = (s: string) =>
  new Date(s).toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });
const plain = (s: string) =>
  s.replace(/\(Citation:[^)]+\)/g, "").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
function download(text: string, name: string, type: string) {
  const u = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = u;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 1000);
}
function Picker({
  label,
  value,
  onChange,
  items,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  items: { value: string; label: string }[];
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v ?? "all")} items={items}>
      <SelectTrigger aria-label={label} className="picker">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {items.map((x) => (
          <SelectItem key={x.value} value={x.value}>
            {x.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
function Cvss({ id }: { id: string }) {
  const [state, setState] = useState<any>(null);
  useEffect(() => {
    setState(null);
    const c = new AbortController();
    loadCvss(id, c.signal)
      .then(setState)
      .catch((e) => {
        if (e.name !== "AbortError") setState({ error: "CVSS enrichment unavailable." });
      });
    return () => c.abort();
  }, [id]);
  return (
    <section className="detail-section">
      <h3>CVSS assessment</h3>
      {!state ? (
        <p>Looking up the CVE record…</p>
      ) : state.metrics?.length ? (
        <>
          <p>
            <strong className="cvss-score">{state.metrics[0].baseScore}</strong>{" "}
            {state.metrics[0].baseSeverity || ""} · CVSS {state.metrics[0].version}
          </p>
          <p className="mono wrap">{state.metrics[0].vectorString}</p>
          <p className="muted">
            Reported by {state.metrics[0].provider}. Severity describes impact; EPSS estimates
            exploitation likelihood.
          </p>
        </>
      ) : (
        <p>{state.error || "No CVSS score is published in this CVE record."}</p>
      )}
    </section>
  );
}
export default function Home() {
  const [data, setData] = useState<Intelligence | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  const [q, setQ] = useState(""),
    [vendor, setVendor] = useState("all"),
    [level, setLevel] = useState("all"),
    [month, setMonth] = useState("all"),
    [page, setPage] = useState(0),
    [selected, setSelected] = useState<Vulnerability | null>(null),
    [group, setGroup] = useState<Group | null>(null),
    [tab, setTab] = useState("overview");
  async function load() {
    setLoading(true);
    setError("");
    try {
      setData(await loadIntelligence(`${import.meta.env.BASE_URL}data/intelligence.json`));
    } catch {
      setError("Intelligence could not be loaded. Please try again.");
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  useEffect(() => setPage(0), [q, vendor, level, month]);
  const all = data?.vulnerabilities || [];
  const rows = useMemo(
    () =>
      filterRecords(all, q, vendor, level).filter(
        (r) => month === "all" || r.added.startsWith(month),
      ),
    [all, q, vendor, level, month],
  );
  const vendors = useMemo(
    () =>
      Array.from(new Set(all.map((x) => x.vendor)))
        .sort()
        .map((v) => ({ value: v, label: v })),
    [all],
  );
  const vendorCounts = useMemo(
    () =>
      Object.entries(
        rows.reduce(
          (a, v) => ({ ...a, [v.vendor]: (a[v.vendor] || 0) + 1 }),
          {} as Record<string, number>,
        ),
      )
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5),
    [rows],
  );
  const months = useMemo(() => {
    const anchor = new Date(data?.catalogDate || Date.now());
    return Array.from({ length: 6 }, (_, i) => {
      const d = new Date(Date.UTC(anchor.getUTCFullYear(), anchor.getUTCMonth() - 5 + i, 1));
      const key = d.toISOString().slice(0, 7);
      return {
        key,
        label: d.toLocaleDateString("en-GB", {
          month: "short",
          timeZone: "UTC",
        }),
        count: filterRecords(all, q, vendor, level).filter((v) => v.added.startsWith(key)).length,
      };
    });
  }, [data, all, q, vendor, level]);
  const groups = (data?.groups || []).filter((g) =>
    `${g.name} ${g.id} ${g.aliases.join(" ")} ${g.description} ${g.techniques.map((t) => t.id + " " + t.name).join(" ")}`
      .toLowerCase()
      .includes(q.toLowerCase().trim()),
  );
  const pageCount = Math.max(1, Math.ceil(rows.length / 12));
  function reset() {
    setQ("");
    setVendor("all");
    setLevel("all");
    setMonth("all");
  }
  function brief() {
    if (!data) return;
    const lines = [
      "# Vulnerability intelligence brief",
      `Prepared ${new Date().toISOString()}`,
      `Data mode: ${data.mode}. KEV catalogue: ${data.catalogDate}. ATT&CK snapshot: ${data.collectedAt}.`,
      "",
      `Scope: ${rows.length} matched KEV records. Search: ${q || "none"}; vendor: ${vendor}; priority: ${level}; month: ${month}.`,
      "",
      "## Assessment",
      "KEV inclusion confirms observed exploitation in the wild. It does not establish exposure or compromise in a specific organisation. Validate affected versions, internet exposure and compensating controls.",
      "",
      "## Items for analyst review",
      ...rows
        .slice(0, 10)
        .flatMap((v) => [
          `### ${v.id} — ${v.vendor} ${v.product}`,
          v.description,
          `Triage: ${priority(v)}. Ransomware use: ${v.ransomware ? "known" : "unknown"}. EPSS: ${v.epss === null ? "not enriched" : (v.epss * 100).toFixed(2) + "% as of " + v.epssDate}.`,
          `CISA action: ${v.action}`,
          `Reference: https://www.cve.org/CVERecord?id=${v.id}`,
          "",
        ]),
      "## Next steps",
      "1. Confirm affected versions against the asset inventory.",
      "2. Review vendor guidance and prioritise exposed systems.",
      "3. Review relevant telemetry with the SOC and document evidence.",
      "4. Escalate confirmed exposure with an owner and remediation plan.",
      "",
      "## Limits",
      "Portfolio research, not an incident finding. Triage labels are not CVSS. EPSS is enriched for the latest 240 KEV entries; missing scores are unknown. CISA due dates are not automatically an organisation’s deadline.",
      "",
      ...data.sources.map((s) => `${s.name}: ${s.url}`),
    ];
    download(lines.join("\n"), "signaldesk-intelligence-brief.md", "text/markdown");
  }
  return (
    <div className="app-shell">
      <header className="topbar">
        <a href={import.meta.env.BASE_URL} className="brand">
          <span className="brand-mark">
            <Radio size={22} />
          </span>
          signaldesk<span className="brand-dot">.</span>
        </a>
        <div className="top-context">THREAT INTELLIGENCE WORKSPACE</div>
        <span className="portfolio">
          <span />
          Public research
        </span>
      </header>
      <main>
        <div className="page-heading">
          <div>
            <div className="eyebrow">
              <span className="small-line" />
              OPEN SOURCE INTELLIGENCE
            </div>
            <h1>From signals to insight.</h1>
            <p className="intro">
              Explore exploited vulnerabilities. Understand adversary behaviour. Follow the
              evidence.
            </p>
          </div>
          <button className="btn refresh" onClick={load} disabled={loading}>
            <RefreshCw size={16} className={loading ? "spin" : ""} />
            {loading ? "Collecting…" : "Refresh feeds"}
          </button>
        </div>
        <div className="status-strip">
          <div>
            <span className={`status-dot ${data?.mode === "live" ? "live" : ""}`} />
            <strong>
              {data?.mode === "live"
                ? "Live collection"
                : data
                  ? "Reference snapshot"
                  : "Connecting to public sources"}
            </strong>
            {data && <span>KEV catalogue · {date(data.catalogDate)}</span>}
          </div>
          <span>
            {data
              ? `Retrieved ${new Date(data.liveAt || data.collectedAt).toLocaleString("en-GB", { timeZone: "UTC" })} UTC`
              : "CISA KEV · FIRST EPSS · MITRE ATT&CK"}
          </span>
        </div>
        {error && (
          <div role="alert" className="notice">
            {error}
            <button onClick={load}>Try again</button>
          </div>
        )}
        {data?.errors.map((e) => (
          <div className="notice" key={e}>
            {e}
          </div>
        ))}
        <Tabs
          value={tab}
          onValueChange={(v) => {
            setTab(String(v));
            setQ("");
          }}
        >
          <div className="nav-row">
            <TabsList variant="line" className="workspace-tabs">
              <TabsTrigger value="overview">
                <Activity size={16} />
                Vulnerability overview
              </TabsTrigger>
              <TabsTrigger value="adversaries">
                <GitBranch size={16} />
                Adversary library
              </TabsTrigger>
              <TabsTrigger value="sources">
                <Database size={16} />
                Sources & methodology
              </TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value="overview">
            <div className="metrics">
              <div className="metric metric-primary">
                <span>Known exploited vulnerabilities</span>
                <strong>{data ? fmt(all.length) : "—"}</strong>
                <small>
                  <Shield size={14} />
                  Evidence of exploitation · CISA KEV
                </small>
              </div>
              <div className="metric">
                <span>Known ransomware use</span>
                <strong>
                  {data ? fmt(all.filter((x) => x.ransomware).length) : "—"}
                  <i className="orange-dot" />
                </strong>
                <small>Unknown is not “no”</small>
              </div>
              <div className="metric">
                <span>Elevated triage priority</span>
                <strong>
                  {data ? fmt(all.filter((x) => priority(x) === "Elevated").length) : "—"}
                </strong>
                <small>Ransomware use or EPSS ≥ 50%</small>
              </div>
              <div className="metric">
                <span>EPSS enrichment coverage</span>
                <strong>
                  {data ? fmt(all.filter((x) => x.epss !== null).length) : "—"}
                  <em> / {data ? fmt(all.length) : "—"}</em>
                </strong>
                <small>Latest 240 KEV entries requested</small>
              </div>
            </div>
            <div className="charts">
              <section className="panel timeline">
                <div className="section-title">
                  <div>
                    <h2>New additions to KEV</h2>
                    <p>Monthly catalogue additions · click a month to filter</p>
                  </div>
                  <span className="legend">
                    <i />
                    Exploited CVEs
                  </span>
                </div>
                <div className="bars" aria-label="Monthly KEV additions">
                  {months.map((m) => (
                    <button
                      aria-pressed={month === m.key}
                      aria-label={`${m.label} ${m.key.slice(0, 4)}: ${m.count} additions`}
                      key={m.key}
                      onClick={() => setMonth(month === m.key ? "all" : m.key)}
                      className={`bar-column ${month === m.key ? "chosen" : ""}`}
                    >
                      <span className="bar-count">{m.count}</span>
                      <span className="bar-track">
                        <span
                          style={{
                            height: `${Math.max(2, (m.count / Math.max(1, ...months.map((x) => x.count))) * 100)}%`,
                          }}
                        />
                      </span>
                      <span>{m.label}</span>
                    </button>
                  ))}
                </div>
              </section>
              <section className="panel vendors">
                <div className="section-title">
                  <div>
                    <h2>Vendors in view</h2>
                    <p>Matched vulnerabilities · click to explore</p>
                  </div>
                  <span className="mini-icon">
                    <Activity size={18} />
                  </span>
                </div>
                <div className="vendor-bars">
                  {vendorCounts.map(([v, n]) => (
                    <button
                      key={v}
                      onClick={() => setVendor(v)}
                      aria-label={`Filter vendor ${v}, ${n} vulnerabilities`}
                    >
                      <span>{v}</span>
                      <strong>{n}</strong>
                      <i>
                        <b
                          style={{
                            width: `${(n / (vendorCounts[0]?.[1] || 1)) * 100}%`,
                          }}
                        />
                      </i>
                    </button>
                  ))}
                  {!rows.length && <p className="muted">No vendors match these filters.</p>}
                </div>
              </section>
            </div>
            <section className="panel intelligence-table">
              <div className="section-title">
                <div>
                  <h2>
                    Intelligence explorer <span className="count-pill">{fmt(rows.length)}</span>
                  </h2>
                  <p>Select a CVE for context, CVSS and further research.</p>
                </div>
                <div className="export-buttons">
                  <button className="text-btn" onClick={brief} disabled={!rows.length}>
                    <FileText size={16} />
                    Export brief
                  </button>
                  <button
                    className="text-btn"
                    onClick={() =>
                      download(toCsv(rows), "signaldesk-vulnerabilities.csv", "text/csv")
                    }
                    disabled={!rows.length}
                  >
                    <ArrowDownToLine size={16} />
                    CSV
                  </button>
                </div>
              </div>
              <div className="filters">
                <label className="searchbox">
                  <Search size={18} />
                  <input
                    aria-label="Search vulnerabilities"
                    placeholder="Search CVE, product, vendor or keyword…"
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                  />
                </label>
                <Picker
                  label="Filter vendor"
                  value={vendor}
                  onChange={setVendor}
                  items={[{ value: "all", label: "All vendors" }, ...vendors]}
                />
                <Picker
                  label="Filter triage priority"
                  value={level}
                  onChange={setLevel}
                  items={[
                    { value: "all", label: "All priorities" },
                    ...["Elevated", "High", "Review"].map((x) => ({
                      value: x,
                      label: x,
                    })),
                  ]}
                />
                {(q || vendor !== "all" || level !== "all" || month !== "all") && (
                  <button className="text-btn" onClick={reset}>
                    Clear{month !== "all" ? ` · ${month}` : ""}
                  </button>
                )}
              </div>
              {loading && !data ? (
                <div className="loading-block">
                  <Skeleton className="h-12 w-full" />
                  <Skeleton className="h-12 w-full" />
                  <p>Collecting public intelligence…</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>VULNERABILITY</TableHead>
                      <TableHead>VENDOR / PRODUCT</TableHead>
                      <TableHead>TRIAGE</TableHead>
                      <TableHead>EPSS</TableHead>
                      <TableHead>RANSOMWARE</TableHead>
                      <TableHead>ADDED TO KEV</TableHead>
                      <TableHead>
                        <span className="sr-only">Details</span>
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.slice(page * 12, page * 12 + 12).map((v) => (
                      <TableRow key={v.id}>
                        <TableCell>
                          <button className="cve-link mono" onClick={() => setSelected(v)}>
                            {v.id}
                          </button>
                          <div className="row-description">{v.title}</div>
                        </TableCell>
                        <TableCell>
                          <strong>{v.vendor}</strong>
                          <div className="muted product-cell">{v.product}</div>
                        </TableCell>
                        <TableCell>
                          <span className={`priority ${priority(v).toLowerCase()}`}>
                            <i />
                            {priority(v)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="mono">
                            {v.epss === null ? "—" : (v.epss * 100).toFixed(1) + "%"}
                          </span>
                        </TableCell>
                        <TableCell>
                          {v.ransomware ? (
                            <span className="ransom-known">Known</span>
                          ) : (
                            <span className="muted">Unknown</span>
                          )}
                        </TableCell>
                        <TableCell className="nowrap">{date(v.added)}</TableCell>
                        <TableCell>
                          <button
                            className="icon-btn"
                            aria-label={`Open ${v.id}`}
                            onClick={() => setSelected(v)}
                          >
                            <ArrowUpRight size={17} />
                          </button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
              {!loading && !rows.length && (
                <div className="empty">
                  <Search size={28} />
                  <h3>No matching intelligence</h3>
                  <p>Try a broader keyword or clear the filters.</p>
                  <button className="btn" onClick={reset}>
                    Clear filters
                  </button>
                </div>
              )}
              <div className="table-footer">
                <span>
                  {rows.length
                    ? `${page * 12 + 1}–${Math.min((page + 1) * 12, rows.length)} of ${fmt(rows.length)} records`
                    : "0 records"}{" "}
                  · EPSS “—” means not enriched
                </span>
                <div>
                  <button
                    className="icon-btn"
                    disabled={page === 0}
                    aria-label="Previous page"
                    onClick={() => setPage((p) => p - 1)}
                  >
                    <ChevronLeft size={17} />
                  </button>
                  <span>
                    Page {page + 1} of {pageCount}
                  </span>
                  <button
                    className="icon-btn"
                    disabled={page + 1 >= pageCount}
                    aria-label="Next page"
                    onClick={() => setPage((p) => p + 1)}
                  >
                    <ChevronRight size={17} />
                  </button>
                </div>
              </div>
            </section>
          </TabsContent>
          <TabsContent value="adversaries">
            <section className="panel library">
              <div className="section-title">
                <div>
                  <h2>Adversary research library</h2>
                  <p>
                    {groups.length} groups from MITRE ATT&CK · snapshot{" "}
                    {data ? date(data.collectedAt) : "loading"}
                  </p>
                </div>
                <span className="badge">Sourced relationships</span>
              </div>
              <label className="searchbox">
                <Search size={18} />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search actor, alias or technique, e.g. FIN7 or T1059"
                  aria-label="Search adversaries"
                />
              </label>
              <p className="library-note">
                Published group-to-technique relationships are historical observations, not claims
                of current activity or attribution to a CVE.
              </p>
              <div className="group-grid">
                {groups.slice(0, 60).map((g) => (
                  <button key={g.id} className="group-card" onClick={() => setGroup(g)}>
                    <span className="mono muted">
                      {g.id}
                      <ArrowUpRight size={16} />
                    </span>
                    <h3>{g.name}</h3>
                    <p>{plain(g.description)}</p>
                    <span className="tech-count">{g.techniques.length} documented techniques</span>
                  </button>
                ))}
              </div>
              {groups.length > 60 && (
                <p className="library-note">Showing 60 groups. Search to narrow the library.</p>
              )}
              {!groups.length && (
                <div className="empty">
                  <h3>No matching groups</h3>
                  <p>Try another alias or technique identifier.</p>
                </div>
              )}
            </section>
          </TabsContent>
          <TabsContent value="sources">
            <section className="panel methodology">
              <div className="section-title">
                <div>
                  <h2>Every signal has a source.</h2>
                  <p>Collection status, interpretation and research boundaries.</p>
                </div>
              </div>
              <div className="source-grid">
                {data?.sources.map((s, i) => (
                  <article key={s.name}>
                    <span className="source-number">0{i + 1}</span>
                    <h3>{s.name}</h3>
                    <strong>{fmt(s.records)} records</strong>
                    <p>
                      {i === 0
                        ? "Evidence of exploitation in the wild. Retrieved from the public CISA feed when you open or refresh the dashboard."
                        : i === 1
                          ? "Estimated probability of exploitation in the next 30 days. The latest 240 KEV records are enriched; missing data remains unknown."
                          : "Published adversary groups and direct technique relationships. A dated snapshot, not a live activity feed."}
                    </p>
                    <a href={s.url} target="_blank" rel="noopener noreferrer">
                      Inspect source <ArrowUpRight size={15} />
                    </a>
                  </article>
                ))}
              </div>
              <div className="method-columns">
                <article>
                  <h3>How triage works</h3>
                  <p>
                    <strong>Elevated:</strong> known ransomware use or EPSS ≥ 50%.{" "}
                    <strong>High:</strong> EPSS ≥ 10%. <strong>Review:</strong> all other records,
                    including missing scores.
                  </p>
                  <p>
                    All records are already in KEV. These labels are a transparent portfolio
                    heuristic, not CVSS severity, a complete risk score, or a reason to ignore
                    “Review” items.
                  </p>
                  <h3>From intelligence to action</h3>
                  <p>
                    Validate affected versions and exposure against your inventory. Review vendor
                    guidance, check telemetry, and communicate confirmed exposure with an owner and
                    remediation plan.
                  </p>
                </article>
                <article>
                  <h3>Scope and limitations</h3>
                  <p>
                    This research workspace uses public data. It has no private asset inventory, SOC
                    telemetry or commercial feeds. It cannot establish whether an organisation is
                    vulnerable or compromised.
                  </p>
                  <p>
                    CISA due dates reflect the applicable US federal directive. They are source
                    context, not a private organisation’s deadline. CVSS is fetched from CVE Program
                    records when a vulnerability is opened.
                  </p>
                  <p>
                    Reference snapshot: {data ? date(data.collectedAt) : "loading"}. Collection
                    failures are explicitly labelled. Refresh retrieves the public feeds again. The
                    bundled reference data is refreshed by the daily publishing workflow. This is
                    not a continuous alerting service.
                  </p>
                </article>
              </div>
            </section>
          </TabsContent>
        </Tabs>
        <footer className="footer">
          <span>
            <Radio size={15} />
            SignalDesk · Independent CTI portfolio project
          </span>
          <span>CISA KEV / FIRST EPSS / MITRE ATT&CK</span>
        </footer>
      </main>
      <Sheet
        open={!!selected}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <SheetContent className="detail-sheet sm:max-w-xl">
          {selected && (
            <>
              <SheetHeader>
                <span className="eyebrow">VULNERABILITY DOSSIER</span>
                <SheetTitle className="mono">{selected.id}</SheetTitle>
                <SheetDescription>{selected.title}</SheetDescription>
              </SheetHeader>
              <div className="detail-body">
                <div className="detail-badges">
                  <span className={`priority ${priority(selected).toLowerCase()}`}>
                    {priority(selected)} triage
                  </span>
                  <span className="badge">CISA KEV confirmed</span>
                </div>
                <section className="detail-section">
                  <h3>What is known</h3>
                  <p>{selected.description}</p>
                  <dl>
                    <dt>Product</dt>
                    <dd>
                      {selected.vendor} · {selected.product}
                    </dd>
                    <dt>Added to KEV</dt>
                    <dd>{date(selected.added)}</dd>
                    <dt>Ransomware use</dt>
                    <dd>{selected.ransomware ? "Known" : "Unknown"}</dd>
                    <dt>EPSS</dt>
                    <dd>
                      {selected.epss === null
                        ? "Not enriched"
                        : `${(selected.epss * 100).toFixed(2)}% · ${selected.epssDate}`}
                    </dd>
                    <dt>Weaknesses</dt>
                    <dd>{selected.cwes.join(", ") || "Not supplied"}</dd>
                  </dl>
                </section>
                <Cvss id={selected.id} />
                <section className="detail-section">
                  <h3>Recommended action from CISA</h3>
                  <p>{selected.action}</p>
                  <p className="muted">
                    CISA directive due date: {date(selected.due)}. Validate local applicability and
                    affected versions.
                  </p>
                </section>
                <section className="detail-section">
                  <h3>Continue the investigation</h3>
                  {[
                    {
                      label: "CVE Program record",
                      url: `https://www.cve.org/CVERecord?id=${selected.id}`,
                    },
                    {
                      label: "NVD and vendor references",
                      url: `https://nvd.nist.gov/vuln/detail/${selected.id}`,
                    },
                    {
                      label: "CISA catalogue entry",
                      url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(selected.id)}`,
                    },
                    {
                      label: "Search advisories and detections",
                      url: `https://www.google.com/search?q=${encodeURIComponent(selected.id + " advisory detection")}`,
                    },
                  ].map((l) => (
                    <a
                      key={l.label}
                      className="research-link"
                      href={l.url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {l.label}
                      <ArrowUpRight size={16} />
                    </a>
                  ))}
                </section>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
      <Sheet
        open={!!group}
        onOpenChange={(open) => {
          if (!open) setGroup(null);
        }}
      >
        <SheetContent className="detail-sheet sm:max-w-xl">
          {group && (
            <>
              <SheetHeader>
                <span className="eyebrow">MITRE ATT&CK GROUP · {group.id}</span>
                <SheetTitle>{group.name}</SheetTitle>
                <SheetDescription>{group.aliases.join(" · ")}</SheetDescription>
              </SheetHeader>
              <div className="detail-body">
                <p>{plain(group.description)}</p>
                <a
                  className="research-link"
                  href={group.url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Full profile and citations
                  <ArrowUpRight size={16} />
                </a>
                <p className="muted">
                  Source modified {date(group.modified)}. Direct “uses” relationships only.
                </p>
                <h3 className="tech-title">Documented techniques ({group.techniques.length})</h3>
                {group.techniques.map((t) => (
                  <a
                    className="technique"
                    key={t.id}
                    href={t.url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <span className="mono">{t.id}</span>
                    <strong>{t.name}</strong>
                    <small>{t.tactics.join(" / ").replaceAll("-", " ")}</small>
                    <ArrowUpRight size={14} />
                  </a>
                ))}
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

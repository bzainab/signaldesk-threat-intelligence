import { test } from "node:test";
import assert from "node:assert/strict";
import { loadIntelligence, loadCvss } from "../lib/feeds.ts";

const snapshot = {
  collectedAt: "2026-09-21",
  catalogDate: "2026-09-21",
  vulnerabilities: [],
  groups: [],
  sources: [],
  errors: [],
};
const kev = {
  dateReleased: "2026-09-21",
  vulnerabilities: [
    {
      cveID: "CVE-2024-3400",
      dateAdded: "2024-04-12",
      vendorProject: "Palo Alto Networks",
      product: "PAN-OS",
      knownRansomwareCampaignUse: "Known",
    },
  ],
};
const response = (data: unknown) => new Response(JSON.stringify(data));

test("unavailable live feed uses a labelled reference snapshot", async () => {
  const data = await loadIntelligence("/data.json", async (url) => {
    if (url === "/data.json") return response(snapshot);
    throw new Error("Network unavailable");
  });
  assert.equal(data.mode, "snapshot");
  assert.match(data.errors[0], /Live collection is unavailable/);
  assert.equal(data.collectedAt, snapshot.collectedAt);
});

test("failed EPSS leaves scores unknown while retaining live KEV records", async () => {
  const data = await loadIntelligence("/data.json", async (url) => {
    if (url === "/data.json") return response(snapshot);
    if (String(url).includes("kev-data")) return response(kev);
    return new Response("", { status: 503 });
  });
  assert.equal(data.mode, "live");
  assert.equal(data.vulnerabilities[0].epss, null);
  assert.equal(data.vulnerabilities[0].ransomware, true);
  assert.equal(data.errors.length, 1);
});

test("live EPSS is associated with the matching CVE and retains its date", async () => {
  const data = await loadIntelligence("/data.json", async (url) => {
    if (url === "/data.json") return response(snapshot);
    if (String(url).includes("kev-data")) return response(kev);
    return response({
      data: [{ cve: "CVE-2024-3400", epss: "0.97", percentile: "0.99", date: "2026-09-20" }],
    });
  });
  assert.equal(data.vulnerabilities[0].epss, 0.97);
  assert.equal(data.vulnerabilities[0].epssDate, "2026-09-20");
});

test("CVSS validation rejects arbitrary URLs before any request", async () => {
  let called = false;
  await assert.rejects(
    loadCvss("https://example.com", undefined, async () => {
      called = true;
      return response({});
    }),
    /Invalid CVE/,
  );
  assert.equal(called, false);
});

test("CVSS extraction preserves contributor attribution and vector", async () => {
  const data = await loadCvss("CVE-2024-3400", undefined, async () =>
    response({
      containers: {
        cna: {
          providerMetadata: { shortName: "Example CNA" },
          metrics: [
            {
              cvssV3_1: {
                baseScore: 9.8,
                vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                version: "3.1",
              },
            },
          ],
        },
      },
    }),
  );
  assert.equal(data.metrics[0].provider, "Example CNA");
  assert.equal(data.metrics[0].baseScore, 9.8);
});

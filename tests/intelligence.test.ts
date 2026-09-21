import { test } from "node:test";
import assert from "node:assert/strict";
import {
  priority,
  filterRecords,
  csvCell,
  toCsv,
  type Vulnerability,
} from "../lib/intelligence.ts";
const record: Vulnerability = {
  id: "CVE-2024-3400",
  title: "Gateway vulnerability",
  vendor: "Palo Alto Networks",
  product: "PAN-OS",
  description: "Remote command injection",
  added: "2024-04-12",
  due: "2024-04-19",
  ransomware: false,
  action: "Update",
  notes: "",
  cwes: ["CWE-77"],
  epss: null,
  percentile: null,
  epssDate: null,
};
test("missing probability is unknown and does not create elevated status", () =>
  assert.equal(priority(record), "Review"));
test("known ransomware use elevates a record even without EPSS", () =>
  assert.equal(priority({ ...record, ransomware: true }), "Elevated"));
test("triage thresholds include boundary values", () => {
  assert.equal(priority({ ...record, epss: 0.5 }), "Elevated");
  assert.equal(priority({ ...record, epss: 0.1 }), "High");
  assert.equal(priority({ ...record, epss: 0.099 }), "Review");
});
test("search is case insensitive and combines words and vendor filter", () => {
  assert.equal(filterRecords([record], "pAn command", "Palo Alto Networks", "all").length, 1);
  assert.equal(filterRecords([record], "pan absent", "all", "all").length, 0);
  assert.equal(filterRecords([record], "", "Microsoft", "all").length, 0);
});
test("CSV neutralises formula prefixes and escapes quotes", () => {
  assert.equal(csvCell('=HYPERLINK("a")'), '"\'=HYPERLINK(""a"")"');
  assert.equal(csvCell(" +1"), '"\' +1"');
});
test("CSV retains unknown probability as an empty field", () =>
  assert.match(toCsv([record]), /"Unknown","","","Review"/));

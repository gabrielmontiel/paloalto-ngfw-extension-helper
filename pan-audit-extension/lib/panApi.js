// lib/panApi.js
// Thin wrapper around the PAN-OS XML API (https://<host>/api/).
// Docs: PAN-OS XML API reference, "Get Started with the PAN-OS XML API".
//
// Everything is sent as POST with a form body, not GET with a query string.
// The original version of this file used GET, which puts the API key (and,
// during keygen, the *password*) directly in the URL — that's the kind of
// thing that ends up in browser history and web-server access logs. PAN-OS
// supports POST identically for every request type, so there's no downside.

import { parseXml, unwrapApiResponse, child, children, entryName, textOf } from "./xmlUtils.js";

export function baseUrlFor(target) {
  const port = target.port && target.port !== 443 ? `:${target.port}` : "";
  return `https://${target.host}${port}`;
}

async function apiCall(baseUrl, params) {
  let res;
  try {
    res = await fetch(`${baseUrl}/api/`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params).toString(),
    });
  } catch (e) {
    // Most common cause: the browser doesn't trust the mgmt interface's
    // (self-signed) certificate yet, or the host permission wasn't granted.
    throw new Error(
      `Network request to ${baseUrl} failed. If this is the first time connecting, ` +
        `open https://${new URL(baseUrl).host} directly in a browser tab and accept the ` +
        `certificate warning, then try again. Original error: ${e.message}`
    );
  }
  const text = await res.text();
  const doc = parseXml(text);
  return unwrapApiResponse(doc);
}

// Exchanges username/password for an API key. The password is used once,
// here, and never persisted by this extension — only the returned key is.
export async function keygen(baseUrl, username, password) {
  const result = await apiCall(baseUrl, { type: "keygen", user: username, password });
  const key = result.querySelector("key")?.textContent?.trim();
  if (!key) throw new Error("Keygen succeeded but no <key> was returned.");
  return key;
}

async function op(baseUrl, apiKey, cmdXml) {
  return apiCall(baseUrl, { type: "op", cmd: cmdXml, key: apiKey });
}

export async function getSystemInfo(baseUrl, apiKey) {
  const result = await op(baseUrl, apiKey, "<show><system><info></info></system></show>");
  const info = result.querySelector("system");
  return {
    hostname: info?.querySelector("hostname")?.textContent?.trim() || "unknown",
    model: info?.querySelector("model")?.textContent?.trim() || "unknown",
    swVersion: info?.querySelector("sw-version")?.textContent?.trim() || "unknown",
    // Panorama's "show system info" model field reads "Panorama".
    isPanorama: /panorama/i.test(info?.querySelector("model")?.textContent || ""),
  };
}

// Single call that returns the full *running* (active/committed, and on a
// managed firewall, Panorama-pushed) config as one XML document — works the
// same way on a standalone firewall and on Panorama itself.
export async function getRunningConfig(baseUrl, apiKey) {
  const result = await op(baseUrl, apiKey, "<show><config><running></running></config></show>");
  const config = result.querySelector("config");
  if (!config) throw new Error("Running-config result did not contain a <config> element.");
  return config;
}

// ---------- candidate config (uncommitted edits) ----------

// type=config&action=get with an xpath returns whatever element the xpath
// points at, wrapped in <result>. xpath='/config' gets the whole candidate
// tree — this is deliberately a *different* call from getRunningConfig:
// running is "what's active now"; candidate is "what's staged but not yet
// committed" (which is exactly where a script should stage new/edited rules
// for a human to review before commit).
export async function getConfig(baseUrl, apiKey, xpath) {
  const result = await apiCall(baseUrl, { type: "config", action: "get", xpath, key: apiKey });
  return result.firstElementChild;
}

export async function getCandidateConfig(baseUrl, apiKey) {
  const config = await getConfig(baseUrl, apiKey, "/config");
  if (!config) throw new Error("Candidate-config result was empty.");
  return config;
}

// Creates (or overwrites, if the named entry already exists at that xpath)
// a configuration node. Used to push a generated rule/object into the
// *candidate* config — never running, never auto-committed. elementXml must
// be the full element for whatever the xpath's container holds, e.g. for a
// rules container xpath, elementXml is a whole <entry name="...">...</entry>.
export async function setConfigNode(baseUrl, apiKey, xpath, elementXml) {
  const result = await apiCall(baseUrl, {
    type: "config",
    action: "set",
    xpath,
    element: elementXml,
    key: apiKey,
  });
  return result; // PAN-OS returns an empty <result/> on success for action=set
}

// ---------- ad hoc / dynamic reports ----------
//
// PAN-OS's "Get Reports" API lets you re-run a report definition ad hoc,
// scoped to a specific query/time window, and get back data PAN-OS already
// aggregated (a "summary" database) instead of raw log rows — much faster
// than pulling and parsing traffic logs client-side, which is exactly why
// this is used for the Policy Optimizer's traffic analysis.
//
// The safe, documented way to do this is to reuse a *Custom Report*
// definition you've already built and saved once via the GUI (Monitor >
// Manage Custom Reports) rather than guessing at summary-database schema —
// PAN-OS's own docs example for ad hoc reports explicitly recommends
// fetching an existing definition via a Config Get call first. See
// README.md's "Setting up a Custom Report" section.

// Fetches a saved report definition's <type>/<period>/<topn>/<query> fields
// so they can be reused (and partially overridden) in an ad hoc run.
// xpath should point at the specific report entry, e.g.
//   /config/shared/reports/entry[@name='rule-traffic-breakdown']
// or, for a per-vsys report on a firewall:
//   /config/devices/entry[@name='...']/vsys/entry[@name='vsys1']/reports/entry[@name='...']
export async function getReportDefinition(baseUrl, apiKey, xpath) {
  const entry = await getConfig(baseUrl, apiKey, xpath);
  if (!entry) throw new Error(`No report definition found at ${xpath}.`);
  return entry;
}

export async function listReportDefinitions(baseUrl, apiKey, containerXpath) {
  const container = await getConfig(baseUrl, apiKey, containerXpath);
  if (!container) return [];
  return children(container, "entry").map((e) => entryName(e));
}

// Builds the <type> element for a traffic-summary report grouped by rule,
// with exactly the columns the Policy Optimizer needs. This lets the
// extension run the report *itself* (as a dynamic ad hoc job) instead of
// requiring you to pre-build and name a saved Custom Report in the GUI.
//
// <trsum> is the traffic-summary database; <aggregate-by> are the group-by
// columns (returned as row tags: rule/src/dst/app/dport — the same names
// policyGenerator's COLUMN_ALIASES already match), and <values> are the
// numeric aggregates PAN-OS needs to have at least one of. Kept as a single
// self-contained function so it's easy to tweak per PAN-OS version.
export function trafficSummaryReportTypeXml() {
  return (
    "<type><trsum>" +
    "<aggregate-by>" +
    "<member>rule</member>" +
    "<member>src</member>" +
    "<member>dst</member>" +
    "<member>app</member>" +
    "<member>dport</member>" +
    "</aggregate-by>" +
    "<values><member>sessions</member><member>bytes</member></values>" +
    "</trsum></type>"
  );
}

// Submits an ad hoc dynamic report job from a raw <type> XML string. This is
// the core used both by the app-built report (trafficSummaryReportTypeXml)
// and by submitAdHocReport (which reuses a saved definition's <type>).
// query/period/topn scope this specific run.
export async function submitAdHocReportFromType(baseUrl, apiKey, typeXml, { query, period, topn }) {
  const cmd =
    typeXml +
    `<period>${escapeXml(period || "last-7-days")}</period>` +
    `<topn>${Number(topn) || 100}</topn>` +
    `<topm>${Number(topn) || 100}</topm>` +
    (query ? `<query>${escapeXml(query)}</query>` : "");

  const result = await apiCall(baseUrl, {
    type: "report",
    reporttype: "dynamic",
    reportname: "pan-audit-adhoc",
    cmd,
    key: apiKey,
  });
  const jobId = result.querySelector("job")?.textContent?.trim();
  if (!jobId) throw new Error("Report submission did not return a job ID.");
  return jobId;
}

// Submits an ad hoc dynamic report job reusing a saved definition's <type>
// (fetched by getReportDefinition). Kept for callers that still want to point
// at a hand-built Custom Report instead of the app-built one.
export async function submitAdHocReport(baseUrl, apiKey, definitionEntryEl, opts) {
  const typeEl = child(definitionEntryEl, "type");
  if (!typeEl) throw new Error("Report definition has no <type> element to reuse.");
  return submitAdHocReportFromType(baseUrl, apiKey, typeEl.outerHTML, opts);
}

export async function getReportJobResult(baseUrl, apiKey, jobId) {
  return apiCall(baseUrl, { type: "report", action: "get", "job-id": jobId, key: apiKey });
}

// Polls a report job until it finishes, then returns parsed rows as plain
// objects (one per <entry>, keyed by whatever column tags PAN-OS returned —
// this deliberately doesn't assume specific column names, since those
// depend entirely on the report definition you built).
export async function pollReportJob(baseUrl, apiKey, jobId, { intervalMs = 2000, timeoutMs = 60000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await getReportJobResult(baseUrl, apiKey, jobId);
    const status = result.querySelector("job > status")?.textContent?.trim();
    if (status === "FIN") {
      const entries = Array.from(result.querySelectorAll("result > entry"));
      return entries.map((e) => {
        const row = {};
        for (const col of e.children) row[col.tagName] = col.textContent.trim();
        return row;
      });
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`Report job ${jobId} did not finish within ${timeoutMs}ms.`);
}

function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]));
}

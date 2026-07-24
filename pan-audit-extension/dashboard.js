import "./lib/navbar.js";
import { getTargets, TARGETS_KEY } from "./lib/store.js";
import {
  baseUrlFor,
  getRunningConfig,
  getCandidateConfig,
  listReportDefinitions,
  getReportDefinition,
  submitAdHocReport,
  pollReportJob,
  setConfigNode,
} from "./lib/panApi.js";
import { runAudit } from "./lib/auditEngine.js";
import {
  summarizeRows,
  buildSuggestedRule,
  ruleToEntryXml,
  ruleToSetCommands,
  filterRowsByRule,
  hasRuleColumn,
} from "./lib/policyGenerator.js";

const el = (id) => document.getElementById(id);

let lastAuditResult = null;
let lastTargetLabel = "";
let lastConfigEl = null; // raw <config> DOM element, for XML export
let currentTarget = null; // the saved target object last used to fetch
let allTrafficRows = null; // rows from the single all-traffic report, reused across every rule

// ---------- target dropdown ----------

async function populateTargets(preserveSelection = true) {
  const previous = el("targetSelect").value;
  const targets = await getTargets();
  const select = el("targetSelect");
  select.innerHTML = "";
  if (targets.length === 0) {
    select.innerHTML = '<option value="">No saved targets — add one in Connections</option>';
    el("fetchBtn").disabled = true;
    return;
  }
  el("fetchBtn").disabled = false;
  for (const t of targets) {
    const opt = document.createElement("option");
    opt.value = t.id;
    opt.textContent = `${t.label} (${t.platform}) — ${t.host}`;
    select.appendChild(opt);
  }
  if (preserveSelection && targets.some((t) => t.id === previous)) {
    select.value = previous;
  }
}

// Live refresh: reflect a target added/removed on the Connections page (or
// another tab) immediately, instead of requiring the dashboard tab to be
// manually reloaded.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[TARGETS_KEY]) populateTargets();
});

function setStatus(msg, isError) {
  const bar = el("statusBar");
  bar.textContent = msg;
  bar.className = `status-bar ${isError ? "error" : ""}`;
}

// ---------- fetch + audit ----------

el("fetchBtn").addEventListener("click", async () => {
  const targets = await getTargets();
  const target = targets.find((t) => t.id === el("targetSelect").value);
  if (!target) return;
  currentTarget = target;

  const source = el("configSourceSelect").value; // "running" | "candidate"
  el("fetchBtn").disabled = true;
  setStatus(`Fetching ${source} config from ${target.host}...`);
  el("results").classList.add("hidden");
  allTrafficRows = null; // a new config/target invalidates the cached traffic report

  try {
    const baseUrl = baseUrlFor(target);
    const configEl = source === "candidate" ? await getCandidateConfig(baseUrl, target.apiKey) : await getRunningConfig(baseUrl, target.apiKey);
    lastConfigEl = configEl;

    setStatus("Running audit...");
    const result = runAudit(configEl);
    lastAuditResult = result;
    lastTargetLabel = target.label;
    renderResults(result);
    setStatus(
      `Audited ${result.summary.totalRulesAudited} security rules across ${result.summary.scopeCount} scope(s) on ${target.host} (${source} config).`
    );
    el("exportJsonBtn").disabled = false;
    el("exportCsvBtn").disabled = false;
    el("exportXmlBtn").disabled = false;
  } catch (e) {
    setStatus(e.message, true);
  } finally {
    el("fetchBtn").disabled = false;
  }
});

// ---------- rendering ----------

function renderResults(result) {
  el("results").classList.remove("hidden");

  const cards = [
    ["Rules audited", result.summary.totalRulesAudited],
    ["Disabled rules", result.summary.disabledRuleCount],
    ["Unused objects", result.summary.unusedObjectCount],
    ["Possibly shadowed", result.summary.possiblyShadowedCount],
    ["Best-practice findings", result.summary.bestPracticeFindingCount],
    ["Overly-open rules", result.summary.overlyOpenRuleCount],
  ];
  el("summaryCards").innerHTML = cards
    .map(([lbl, num]) => `<div class="card"><div class="num">${num}</div><div class="lbl">${lbl}</div></div>`)
    .join("");

  renderTable(
    "panel-disabled",
    ["Scope", "Rulebase", "Rule"],
    result.disabledRules.map((r) => [r.scope, r.rulebase, r.name]),
    "No disabled rules found."
  );

  renderTable(
    "panel-unused",
    ["Scope", "Kind", "Name"],
    result.unusedObjects.map((o) => [o.scope, o.kind, o.name]),
    "No unused address/service objects found (note: dynamic address groups can't be statically checked)."
  );

  renderTable(
    "panel-shadowed",
    ["Rulebase", "Shadowing rule", "Shadowed rule", "Why"],
    result.possiblyShadowedRules.map((s) => [s.rulebase, s.shadowingRule, s.shadowedRule, s.reason]),
    "No obviously shadowed rules found (heuristic check — always verify manually)."
  );

  renderTable(
    "panel-bestpractice",
    ["Severity", "Scope", "Rulebase", "Rule", "Issue"],
    result.bestPractice.map((b) => [
      `<span class="badge ${b.severity}">${b.severity}</span>`,
      b.scope,
      b.rulebase,
      b.rule,
      b.issue,
    ]),
    "No best-practice issues found."
  );

  renderOptimizerPanel(result);
}

function renderTable(panelId, headers, rows, emptyMsg) {
  const panel = el(panelId);
  if (rows.length === 0) {
    panel.innerHTML = `<div class="empty">${emptyMsg}</div>`;
    return;
  }
  const thead = `<thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>`;
  const tbody = `<tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody>`;
  panel.innerHTML = `<table>${thead}${tbody}</table>`;
}

document.getElementById("tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
  document.querySelectorAll(".panel").forEach((p) => p.classList.add("hidden"));
  btn.classList.add("active");
  el(`panel-${btn.dataset.tab}`).classList.remove("hidden");
});

// ---------- Policy Optimizer ----------

function renderOptimizerPanel(result) {
  const panel = el("panel-optimizer");
  if (result.overlyOpenRules.length === 0) {
    panel.innerHTML = '<div class="empty">No overly-open allow rules found — nothing to optimize.</div>';
    return;
  }

  panel.innerHTML = `
    <div class="optimizer-config">
      <div class="warn-box">
        Runs <strong>one</strong> ad hoc report over <strong>all</strong> traffic (reusing a saved Custom Report so
        PAN-OS does the aggregation), then reuses it for every rule below — no per-rule reports. The report must include
        a <strong>Rule</strong> column and be grouped by rule, plus source, destination, application, and service/port.
        See the README's "Setting up a Custom Report" section.
      </div>

      <div class="field-row">
        <div>
          <label>Report container xpath</label>
          <input id="optReportXpath" value="/config/shared/reports" />
        </div>
        <div>
          <label>Report name</label>
          <input id="optReportName" placeholder="e.g. all-traffic-by-rule" />
        </div>
        <div style="flex:0 0 auto; align-self:flex-end;">
          <button id="optLoadReports">List available</button>
        </div>
      </div>

      <div class="field-row">
        <div>
          <label>Period</label>
          <select id="optPeriod">
            <option value="last-24-hrs">Last 24 hours</option>
            <option value="last-7-days" selected>Last 7 days</option>
            <option value="last-30-days">Last 30 days</option>
          </select>
        </div>
        <div>
          <label>Top N rows</label>
          <input id="optTopN" value="500" />
        </div>
        <div>
          <label>App-ID blacklist (space-separated)</label>
          <input id="optBlacklist" value="insufficient-data unknown-tcp unknown-udp incomplete" />
        </div>
      </div>

      <div class="modal-actions" style="justify-content:flex-start;">
        <button id="optRunReport" class="primary">Run traffic report (all rules)</button>
      </div>
      <div id="optReportStatus" class="meta" style="margin-top:8px;"></div>
    </div>

    <div class="optimizer-list">
      ${result.overlyOpenRules
        .map(
          (r, i) => `
        <div class="optimizer-row">
          <div>
            <strong>${escapeHtml(r.rule.name)}</strong>
            <div class="meta">${escapeHtml(r.scopeLabel)} — ${escapeHtml(r.rulebaseLabel)} · any in: ${escapeHtml(
            r.anyFields.join(", ")
          )}</div>
          </div>
          <div class="actions">
            <button data-idx="${i}" data-mode="narrow" disabled>Narrow…</button>
            <button data-idx="${i}" data-mode="appid" disabled>Add App-ID…</button>
          </div>
        </div>`
        )
        .join("")}
    </div>
  `;

  el("optLoadReports").addEventListener("click", async () => {
    const status = el("optReportStatus");
    status.textContent = "Loading report list...";
    status.style.color = "";
    try {
      const baseUrl = baseUrlFor(currentTarget);
      const names = await listReportDefinitions(baseUrl, currentTarget.apiKey, el("optReportXpath").value.trim());
      status.textContent = names.length
        ? `Found: ${names.join(", ")}`
        : "No reports found at that xpath. Try /config/shared/reports, or for a per-vsys report on a firewall: /config/devices/entry/vsys/entry[@name='vsys1']/reports";
    } catch (e) {
      status.textContent = e.message;
      status.style.color = "#b41a1a";
    }
  });

  el("optRunReport").addEventListener("click", () => runTrafficReport(panel));

  panel.querySelectorAll("button[data-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.idx);
      generateForRule(result.overlyOpenRules[idx], btn.dataset.mode);
    });
  });
}

// Runs the single all-traffic report once and caches its rows. Every rule's
// Narrow/Add App-ID button then works off this cache — no more one-report-per-rule.
async function runTrafficReport(panel) {
  const status = el("optReportStatus");
  status.style.color = "";
  const reportName = el("optReportName").value.trim();
  if (!reportName) {
    status.textContent = "Enter a report name first.";
    status.style.color = "#b41a1a";
    return;
  }
  const reportXpath = `${el("optReportXpath").value.trim()}/entry[@name='${reportName}']`;
  const period = el("optPeriod").value;
  const topn = el("optTopN").value;

  el("optRunReport").disabled = true;
  try {
    const baseUrl = baseUrlFor(currentTarget);
    status.textContent = "Fetching report definition...";
    const definitionEntry = await getReportDefinition(baseUrl, currentTarget.apiKey, reportXpath);

    // No (rule eq ...) filter — this pulls all traffic in one job, grouped by
    // rule via the report definition, so it can be reused for every rule.
    status.textContent = "Submitting ad hoc report job (all traffic)...";
    const jobId = await submitAdHocReport(baseUrl, currentTarget.apiKey, definitionEntry, { query: "", period, topn });

    status.textContent = `Job ${jobId} running, polling for results...`;
    const rows = await pollReportJob(baseUrl, currentTarget.apiKey, jobId);
    allTrafficRows = rows;

    if (rows.length === 0) {
      status.textContent = "Report returned no rows for this period. Try a longer period.";
      return;
    }
    if (!hasRuleColumn(rows)) {
      status.textContent = `Fetched ${rows.length} rows, but no Rule column was found — traffic can't be attributed per rule. Rebuild the Custom Report with a Rule column grouped by rule.`;
      status.style.color = "#b41a1a";
      return;
    }

    status.textContent = `Fetched ${rows.length} traffic rows. Pick a rule below and click Narrow or Add App-ID.`;
    panel.querySelectorAll("button[data-mode]").forEach((b) => (b.disabled = false));
  } catch (e) {
    status.textContent = e.message;
    status.style.color = "#b41a1a";
  } finally {
    el("optRunReport").disabled = false;
  }
}

// Builds a suggested rule for one rule from the cached all-traffic report and
// shows it (SET commands + push) in the modal. No network report call here.
function generateForRule(overlyOpenRule, mode) {
  if (!allTrafficRows) return;
  const isAppid = mode === "appid";
  const suffix = isAppid ? "-appid" : "-narrowed";
  const blacklist = el("optBlacklist").value.trim().split(/\s+/).filter(Boolean);

  const root = el("optimizerModalRoot");
  const out = () => el("optOutput");

  const ruleRows = filterRowsByRule(allTrafficRows, overlyOpenRule.rule.name);

  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal modal-wrap">
        <button class="close-x" id="modalClose">✕</button>
        <h2>${isAppid ? "Add App-ID" : "Narrow policy"}: ${escapeHtml(overlyOpenRule.rule.name)}</h2>
        <div class="subtitle">${escapeHtml(overlyOpenRule.scopeLabel)} — ${escapeHtml(
    overlyOpenRule.rulebaseLabel
  )} · any in: ${escapeHtml(overlyOpenRule.anyFields.join(", "))}</div>
        <div id="optOutput"></div>
      </div>
    </div>
  `;
  el("modalClose").addEventListener("click", () => (root.innerHTML = ""));
  root.querySelector(".modal-backdrop").addEventListener("click", (e) => {
    if (e.target.classList.contains("modal-backdrop")) root.innerHTML = "";
  });

  if (ruleRows.length === 0) {
    out().innerHTML =
      '<p class="meta">No traffic rows for this rule in the report. It may have had no traffic in the selected period, or the report\'s Rule column names don\'t match this rule.</p>';
    return;
  }

  const summary = summarizeRows(ruleRows, { appBlacklist: blacklist });
  const suggested = buildSuggestedRule(overlyOpenRule.rule, summary, { mode, suffix, anyFields: overlyOpenRule.anyFields });
  const entryXml = ruleToEntryXml(suggested);
  const setCommands = ruleToSetCommands(suggested, {
    deviceEntryName: overlyOpenRule.deviceEntryName,
    scopeKind: overlyOpenRule.scopeKind,
    scopeName: overlyOpenRule.scopeName,
    rulebaseTag: overlyOpenRule.rulebaseTag,
  });

  out().innerHTML = `
    <p class="meta">${ruleRows.length} traffic rows for this rule. Suggested rule: <strong>${escapeHtml(
    suggested.name
  )}</strong></p>
    <table class="summary-table">
      <tr><th>Sources observed</th><td>${summary.sources.length}</td></tr>
      <tr><th>Destinations observed</th><td>${summary.destinations.length}</td></tr>
      <tr><th>Applications observed</th><td>${escapeHtml(summary.applications.join(", ")) || "none (after blacklist)"}</td></tr>
    </table>
    <label>SET commands</label>
    <textarea class="code" rows="8" readonly>${escapeHtml(setCommands)}</textarea>
    <div class="modal-actions">
      <button id="optCopy">Copy SET commands</button>
      <button id="optDownload">Download .txt</button>
      <button id="optPush" class="primary">Push new rule to candidate config</button>
    </div>
    <div id="optPushStatus" class="meta" style="margin-top:8px;"></div>
  `;

  el("optCopy").addEventListener("click", () => navigator.clipboard.writeText(setCommands));
  el("optDownload").addEventListener("click", () => downloadFile(`${suggested.name}.txt`, setCommands, "text/plain"));
  el("optPush").addEventListener("click", async () => {
    const confirmed = confirm(
      `This adds a NEW rule "${suggested.name}" to the CANDIDATE config (not committed, not running). ` +
        `You'll still need to review and commit it yourself. Continue?`
    );
    if (!confirmed) return;
    const status = el("optPushStatus");
    status.textContent = "Pushing...";
    try {
      await setConfigNode(baseUrlFor(currentTarget), currentTarget.apiKey, overlyOpenRule.containerXpath, entryXml);
      status.textContent = `Done — "${suggested.name}" is now in the candidate config. Review and commit from the firewall/Panorama when ready.`;
    } catch (e) {
      status.textContent = `Failed: ${e.message}`;
      status.style.color = "#b41a1a";
    }
  });
}

// ---------- exports ----------

el("exportJsonBtn").addEventListener("click", () => {
  downloadFile(`pan-audit-${slug(lastTargetLabel)}.json`, JSON.stringify(lastAuditResult, null, 2), "application/json");
});

el("exportCsvBtn").addEventListener("click", () => {
  const rows = [["section", "field1", "field2", "field3", "field4"]];
  for (const r of lastAuditResult.disabledRules) rows.push(["disabled_rule", r.scope, r.rulebase, r.name, ""]);
  for (const o of lastAuditResult.unusedObjects) rows.push(["unused_object", o.scope, o.kind, o.name, ""]);
  for (const s of lastAuditResult.possiblyShadowedRules)
    rows.push(["possible_shadow", s.rulebase, s.shadowingRule, s.shadowedRule, s.reason]);
  for (const b of lastAuditResult.bestPractice)
    rows.push(["best_practice", b.severity, b.scope, b.rulebase, `${b.rule}: ${b.issue}`]);

  const csv = rows.map((r) => r.map(csvEscape).join(",")).join("\n");
  downloadFile(`pan-audit-${slug(lastTargetLabel)}.csv`, csv, "text/csv");
});

el("exportXmlBtn").addEventListener("click", () => {
  if (!lastConfigEl) return;
  const xml = new XMLSerializer().serializeToString(lastConfigEl);
  downloadFile(`pan-config-${slug(lastTargetLabel)}.xml`, xml, "application/xml");
});

function csvEscape(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function slug(s) {
  return (s || "target").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

populateTargets();

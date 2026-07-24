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
import { summarizeRows, buildSuggestedRule, ruleToEntryXml, ruleToSetCommands } from "./lib/policyGenerator.js";

const el = (id) => document.getElementById(id);

let lastAuditResult = null;
let lastTargetLabel = "";
let lastConfigEl = null; // raw <config> DOM element, for XML export
let currentTarget = null; // the saved target object last used to fetch

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
    ["Any/any/any rules", result.summary.overlyOpenRuleCount],
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
    panel.innerHTML = '<div class="empty">No any/any/any/any allow rules found — nothing to optimize.</div>';
    return;
  }
  panel.innerHTML =
    '<div class="optimizer-list">' +
    result.overlyOpenRules
      .map(
        (r, i) => `
      <div class="optimizer-row">
        <div>
          <strong>${escapeHtml(r.rule.name)}</strong>
          <div class="meta">${escapeHtml(r.scopeLabel)} — ${escapeHtml(r.rulebaseLabel)}</div>
        </div>
        <div class="actions">
          <button data-idx="${i}" data-mode="narrow">Narrow using report…</button>
          <button data-idx="${i}" data-mode="appid">Add App-ID using report…</button>
        </div>
      </div>`
      )
      .join("") +
    "</div>";

  panel.querySelectorAll("button[data-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.idx);
      openOptimizerModal(result.overlyOpenRules[idx], btn.dataset.mode);
    });
  });
}

function openOptimizerModal(overlyOpenRule, mode) {
  const root = el("optimizerModalRoot");
  const isAppid = mode === "appid";
  const defaultSuffix = isAppid ? "-appid" : "-narrowed";

  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal modal-wrap">
        <button class="close-x" id="modalClose">✕</button>
        <h2>${isAppid ? "Add App-ID" : "Narrow policy"}: ${escapeHtml(overlyOpenRule.rule.name)}</h2>
        <div class="subtitle">${escapeHtml(overlyOpenRule.scopeLabel)} — ${escapeHtml(overlyOpenRule.rulebaseLabel)}</div>

        <div class="warn-box">
          This reuses a <strong>saved Custom Report</strong> (Monitor &gt; Manage Custom Reports on the firewall/Panorama)
          so PAN-OS does the aggregation, not raw log parsing. It needs source, destination, application, and service/port
          columns to be useful. See the README's "Setting up a Custom Report" section if you haven't made one yet.
        </div>

        <div class="field-row">
          <div>
            <label>Report container xpath</label>
            <input id="optReportXpath" value="/config/shared/reports" />
          </div>
          <div>
            <label>Report name</label>
            <input id="optReportName" placeholder="e.g. rule-traffic-breakdown" />
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
            <input id="optTopN" value="200" />
          </div>
          <div>
            <label>New rule suffix</label>
            <input id="optSuffix" value="${defaultSuffix}" />
          </div>
        </div>

        <div class="field-row">
          <div>
            <label>App-ID blacklist (space-separated)</label>
            <input id="optBlacklist" value="insufficient-data unknown-tcp unknown-udp incomplete" />
          </div>
        </div>

        <div class="modal-actions">
          <button id="optRun" class="primary">Run report &amp; generate</button>
        </div>

        <div id="optOutput"></div>
      </div>
    </div>
  `;

  el("modalClose").addEventListener("click", () => (root.innerHTML = ""));
  root.querySelector(".modal-backdrop").addEventListener("click", (e) => {
    if (e.target.classList.contains("modal-backdrop")) root.innerHTML = "";
  });

  el("optLoadReports").addEventListener("click", async () => {
    const out = el("optOutput");
    out.innerHTML = '<p class="meta">Loading report list...</p>';
    try {
      const baseUrl = baseUrlFor(currentTarget);
      const names = await listReportDefinitions(baseUrl, currentTarget.apiKey, el("optReportXpath").value.trim());
      out.innerHTML = names.length
        ? `<p class="meta">Found: ${names.map(escapeHtml).join(", ")}</p>`
        : '<p class="meta">No reports found at that xpath. Try /config/shared/reports, or for a per-vsys report on a firewall: /config/devices/entry/vsys/entry[@name=\'vsys1\']/reports</p>';
    } catch (e) {
      out.innerHTML = `<p class="meta" style="color:#b41a1a;">${escapeHtml(e.message)}</p>`;
    }
  });

  el("optRun").addEventListener("click", () => runOptimizer(overlyOpenRule, mode));
}

async function runOptimizer(overlyOpenRule, mode) {
  const out = el("optOutput");
  const reportXpath = `${el("optReportXpath").value.trim()}/entry[@name='${el("optReportName").value.trim()}']`;
  const period = el("optPeriod").value;
  const topn = el("optTopN").value;
  const suffix = el("optSuffix").value.trim() || "-narrowed";
  const blacklist = el("optBlacklist").value.trim().split(/\s+/).filter(Boolean);

  if (!el("optReportName").value.trim()) {
    out.innerHTML = '<p class="meta" style="color:#b41a1a;">Enter a report name first.</p>';
    return;
  }

  out.innerHTML = '<p class="meta">Fetching report definition...</p>';
  try {
    const baseUrl = baseUrlFor(currentTarget);
    const definitionEntry = await getReportDefinition(baseUrl, currentTarget.apiKey, reportXpath);

    let query = `(rule eq '${overlyOpenRule.rule.name}')`;
    if (overlyOpenRule.scopeKind === "device-group") {
      query += ` and (device-group eq '${overlyOpenRule.scopeName}')`;
    }

    out.innerHTML = '<p class="meta">Submitting ad hoc report job...</p>';
    const jobId = await submitAdHocReport(baseUrl, currentTarget.apiKey, definitionEntry, { query, period, topn });

    out.innerHTML = `<p class="meta">Job ${escapeHtml(jobId)} running, polling for results...</p>`;
    const rows = await pollReportJob(baseUrl, currentTarget.apiKey, jobId);

    if (rows.length === 0) {
      out.innerHTML = '<p class="meta">Report returned no rows for this rule/period — nothing to suggest. Try a longer period.</p>';
      return;
    }

    const summary = summarizeRows(rows, { appBlacklist: blacklist });
    const suggested = buildSuggestedRule(overlyOpenRule.rule, summary, { mode, suffix });
    const entryXml = ruleToEntryXml(suggested);
    const setCommands = ruleToSetCommands(suggested, {
      deviceEntryName: overlyOpenRule.deviceEntryName,
      scopeKind: overlyOpenRule.scopeKind,
      scopeName: overlyOpenRule.scopeName,
      rulebaseTag: overlyOpenRule.rulebaseTag,
    });

    out.innerHTML = `
      <p class="meta">${rows.length} traffic rows analyzed. Suggested rule: <strong>${escapeHtml(suggested.name)}</strong></p>
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
    el("optDownload").addEventListener("click", () =>
      downloadFile(`${suggested.name}.txt`, setCommands, "text/plain")
    );
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
  } catch (e) {
    out.innerHTML = `<p class="meta" style="color:#b41a1a;">${escapeHtml(e.message)}</p>`;
  }
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

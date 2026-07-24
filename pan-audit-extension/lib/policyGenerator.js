// lib/policyGenerator.js
//
// Takes an overly-open rule (from auditEngine's overlyOpenRules) plus rows
// of observed traffic (from a PAN-OS report — see reportRunner.js) and
// produces a narrower replacement rule, in two forms:
//   - a PAN-OS "set" CLI command block (for pasting into the CLI / Panorama)
//   - a pushable XML <entry> + xpath pair (for setConfigNode)
//
// Two modes, mirroring the two tools this was ported from:
//   - "narrow"  (any_policies.js equivalent): rewrites source, destination,
//     application, and service based on what was actually observed.
//   - "appid"   (appid.js equivalent): only adds application-id values;
//     leaves source/destination untouched, switches service to
//     application-default (PAN-OS best practice once app-id is in play).
//
// Row shape expected: each row is a plain object with *some* subset of
// {source, destination, application, service, port, protocol, bytes,
// sessions} — whatever columns your Custom Report definition returns.
// Column names are matched case-insensitively against a few common aliases
// since different report definitions name them slightly differently.

const COLUMN_ALIASES = {
  source: ["source", "src", "sourceip", "source-ip"],
  destination: ["destination", "dst", "destinationip", "destination-ip"],
  application: ["application", "app"],
  service: ["service", "port", "dport", "destination-port"],
};

function pick(row, kind) {
  const aliases = COLUMN_ALIASES[kind];
  for (const key of Object.keys(row)) {
    if (aliases.includes(key.toLowerCase())) return row[key];
  }
  return null;
}

function uniqueNonEmpty(values) {
  return Array.from(new Set(values.filter((v) => v && v.trim() && v !== "0.0.0.0"))).sort();
}

// Aggregates raw rows into the distinct source/destination/application/service
// values observed, filtering out blacklisted applications (e.g.
// insufficient-data, unknown-tcp, unknown-udp, incomplete — PAN-OS's own
// "not a real classification" markers).
export function summarizeRows(rows, { appBlacklist = [] } = {}) {
  const blacklist = new Set(appBlacklist.map((a) => a.trim().toLowerCase()).filter(Boolean));
  const sources = [];
  const destinations = [];
  const applications = [];
  const services = [];

  for (const row of rows) {
    const src = pick(row, "source");
    const dst = pick(row, "destination");
    const app = pick(row, "application");
    const svc = pick(row, "service");
    if (src) sources.push(src);
    if (dst) destinations.push(dst);
    if (app && !blacklist.has(app.trim().toLowerCase())) applications.push(app);
    if (svc) services.push(svc);
  }

  return {
    sources: uniqueNonEmpty(sources),
    destinations: uniqueNonEmpty(destinations),
    applications: uniqueNonEmpty(applications),
    services: uniqueNonEmpty(services),
  };
}

// Builds the suggested new rule as a plain object (not yet XML), applying
// the "narrow" or "appid" strategy on top of the original rule's other
// fields (from/to zones, action, tags — left as-is).
export function buildSuggestedRule(originalRule, summary, { mode = "narrow", suffix = "-narrowed" } = {}) {
  const newName = `${originalRule.name}${suffix}`;

  if (mode === "appid") {
    return {
      name: newName,
      from: originalRule.from,
      to: originalRule.to,
      source: originalRule.source, // unchanged — appid mode only touches app/service
      destination: originalRule.destination,
      application: summary.applications.length ? summary.applications : ["any"],
      service: summary.applications.length ? ["application-default"] : originalRule.service,
      action: originalRule.action,
      tags: originalRule.tags,
    };
  }

  // "narrow" mode
  return {
    name: newName,
    from: originalRule.from,
    to: originalRule.to,
    source: summary.sources.length ? summary.sources : originalRule.source,
    destination: summary.destinations.length ? summary.destinations : originalRule.destination,
    application: summary.applications.length ? summary.applications : originalRule.application,
    service: summary.applications.length ? ["application-default"] : originalRule.service,
    action: originalRule.action,
    tags: originalRule.tags,
  };
}

function memberXml(tag, values) {
  if (!values || values.length === 0) return `<${tag}><member>any</member></${tag}>`;
  return `<${tag}>${values.map((v) => `<member>${escapeXml(v)}</member>`).join("")}</${tag}>`;
}

export function ruleToEntryXml(rule) {
  return (
    `<entry name="${escapeXml(rule.name)}">` +
    memberXml("from", rule.from.length ? rule.from : ["any"]) +
    memberXml("to", rule.to.length ? rule.to : ["any"]) +
    memberXml("source", rule.source) +
    memberXml("destination", rule.destination) +
    memberXml("application", rule.application) +
    memberXml("service", rule.service) +
    `<action>${escapeXml(rule.action)}</action>` +
    (rule.tags.length ? memberXml("tag", rule.tags) : "") +
    `</entry>`
  );
}

// PAN-OS "set" CLI equivalent — useful to paste into a CLI session, or to
// keep as a change record even when pushing via the API instead.
export function ruleToSetCommands(rule, { deviceEntryName, scopeKind, scopeName, rulebaseTag }) {
  const base =
    scopeKind === "device-group"
      ? `set device-group ${quoteIfNeeded(scopeName)} ${rulebaseTag} security rules ${quoteIfNeeded(rule.name)}`
      : scopeKind === "vsys"
      ? `set vsys ${quoteIfNeeded(scopeName)} rulebase security rules ${quoteIfNeeded(rule.name)}`
      : `set shared ${rulebaseTag} security rules ${quoteIfNeeded(rule.name)}`;

  const lines = [
    `${base} from ${rule.from.join(" ")}`,
    `${base} to ${rule.to.join(" ")}`,
    `${base} source ${rule.source.join(" ")}`,
    `${base} destination ${rule.destination.join(" ")}`,
    `${base} application ${rule.application.join(" ")}`,
    `${base} service ${rule.service.join(" ")}`,
    `${base} action ${rule.action}`,
  ];
  if (rule.tags.length) lines.push(`${base} tag [ ${rule.tags.join(" ")} ]`);
  return lines.join("\n");
}

function quoteIfNeeded(s) {
  return /\s/.test(s) ? `"${s}"` : s;
}

function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]));
}

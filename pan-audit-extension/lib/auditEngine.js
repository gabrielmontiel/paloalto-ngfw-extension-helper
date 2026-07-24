// lib/auditEngine.js
//
// Walks a PAN-OS / Panorama running-config <config> element and produces:
//   - disabledRules
//   - possiblyShadowedRules (heuristic, see note below)
//   - unusedObjects (address / address-group / service / service-group)
//   - bestPractice findings
//   - overlyOpenRules — the any/any/any/any subset of bestPractice findings,
//     carried with enough location info (device-group/vsys name, rulebase
//     tag, container xpath) for the Policy Optimizer to act on them.
//
// Scope model
// -----------
// IMPORTANT correction from the first version of this file: Panorama
// device-groups are NOT physically nested in the config XML. They are a
// FLAT list at /config/devices/entry/device-group/entry, and the parent/
// child relationship used for object & rule inheritance is recorded
// separately at /config/readonly/devices/entry/device-group/entry/parent-dg.
// (Verified against Palo Alto's own KB/XML-API examples and community xpath
// dumps — the earlier "recursive <device-group> nesting" assumption was
// wrong and would have produced incorrect xpaths for pushing new rules.)
//
// A firewall in vsys mode has scopes: shared, vsys1, vsys2, ... (flat,
// always parented directly to shared — vsys don't nest).
//
// An object is only "reachable" from rules in its own scope or scopes
// beneath it in the hierarchy, so unused-object detection is done per
// device-group / vsys, walking each one's ancestor chain up to shared.
//
// Known limitations (v1): only the *security* rulebase is analyzed (not
// NAT/decryption/QoS); Panorama templates are not walked; shadow detection
// is a same-or-broader-scope heuristic, not a full field-by-field superset
// proof — treat "possibly shadowed" as "worth a human look", not fact. The
// /config/readonly parent-dg map may be absent in some exports (older
// PAN-OS, or a firewall's own view of pushed policy) — when that happens,
// every device-group falls back to being a direct child of shared, which
// only affects *cross-device-group* object-inheritance resolution, not
// per-device-group rule auditing.

import { children, child, memberList, entryName, textOf } from "./xmlUtils.js";

const ANY_KEYWORDS = new Set(["any"]);

// ---------- scope discovery ----------

function buildScopeTree(configEl) {
  const sharedEl = child(configEl, "shared");
  const sharedScope = {
    id: "shared",
    label: "Shared",
    kind: "shared",
    name: null,
    element: sharedEl,
    parent: null,
  };

  const devicesEl = child(configEl, "devices");
  const deviceEntry = devicesEl ? children(devicesEl, "entry")[0] : null;
  const deviceEntryName = deviceEntry ? entryName(deviceEntry) : "localhost.localdomain";

  if (!deviceEntry) return { sharedScope, scopes: [sharedScope], deviceEntryName };

  const vsysParent = child(deviceEntry, "vsys");
  if (vsysParent) {
    // Firewall (vsys mode) — flat, always parented to shared.
    const scopes = children(vsysParent, "entry").map((vsysEl) => ({
      id: `vsys:${entryName(vsysEl)}`,
      label: `vsys "${entryName(vsysEl)}"`,
      kind: "vsys",
      name: entryName(vsysEl),
      element: vsysEl,
      parent: sharedScope,
    }));
    return { sharedScope, scopes: scopes.length ? scopes : [sharedScope], deviceEntryName };
  }

  const dgParent = child(deviceEntry, "device-group");
  if (dgParent) {
    // Panorama — flat list; parent-dg map comes from /config/readonly.
    const parentMap = readParentDgMap(configEl);
    const dgEntries = children(dgParent, "entry");
    const scopeById = new Map();

    for (const dgEl of dgEntries) {
      const name = entryName(dgEl);
      scopeById.set(name, {
        id: `dg:${name}`,
        label: `device-group "${name}"`,
        kind: "device-group",
        name,
        element: dgEl,
        parent: null, // linked below once all scopes exist
      });
    }
    for (const dgEl of dgEntries) {
      const name = entryName(dgEl);
      const scope = scopeById.get(name);
      const parentName = parentMap.get(name);
      scope.parent = (parentName && scopeById.get(parentName)) || sharedScope;
    }
    const scopes = Array.from(scopeById.values());
    return { sharedScope, scopes: scopes.length ? scopes : [sharedScope], deviceEntryName };
  }

  return { sharedScope, scopes: [sharedScope], deviceEntryName };
}

function readParentDgMap(configEl) {
  const map = new Map();
  const readonlyEl = child(configEl, "readonly");
  const readonlyDevices = readonlyEl ? child(readonlyEl, "devices") : null;
  const readonlyDeviceEntry = readonlyDevices ? children(readonlyDevices, "entry")[0] : null;
  const readonlyDgParent = readonlyDeviceEntry ? child(readonlyDeviceEntry, "device-group") : null;
  if (!readonlyDgParent) return map; // absent in this export — flat fallback
  for (const dgEl of children(readonlyDgParent, "entry")) {
    const name = entryName(dgEl);
    const parentDg = textOf(child(dgEl, "parent-dg"));
    if (parentDg) map.set(name, parentDg);
  }
  return map;
}

function scopeChain(scope) {
  // self -> ... -> shared
  const chain = [];
  let s = scope;
  while (s) {
    chain.push(s);
    s = s.parent;
  }
  return chain;
}

// ---------- xpath helpers (used by the Policy Optimizer to push changes) ----------

export function rulesContainerXpath(deviceEntryName, scope, rulebaseTag) {
  const dev = `/config/devices/entry[@name='${deviceEntryName}']`;
  if (scope.kind === "vsys") {
    return `${dev}/vsys/entry[@name='${scope.name}']/rulebase/security/rules`;
  }
  if (scope.kind === "device-group") {
    return `${dev}/device-group/entry[@name='${scope.name}']/${rulebaseTag}/security/rules`;
  }
  // shared
  return `/config/shared/${rulebaseTag}/security/rules`;
}

// ---------- object collection ----------

function collectObjectsInScope(scope) {
  const el = scope.element;
  return {
    address: indexEntries(child(el, "address")),
    "address-group": indexEntries(child(el, "address-group")),
    service: indexEntries(child(el, "service")),
    "service-group": indexEntries(child(el, "service-group")),
  };
}

function indexEntries(containerEl) {
  const map = new Map();
  for (const e of children(containerEl, "entry")) {
    map.set(entryName(e), e);
  }
  return map;
}

function lookupObject(chain, objectsByScope, kind, name) {
  for (const scope of chain) {
    const objs = objectsByScope.get(scope.id)[kind];
    if (objs.has(name)) return { scope, entry: objs.get(name) };
  }
  return null;
}

// ---------- rulebases ----------

function collectRulebases(scope) {
  // A firewall vsys has one "rulebase"; a Panorama device-group / shared has
  // "pre-rulebase" and "post-rulebase". Each entry carries a rulebaseTag so
  // callers can compute the right xpath ("rulebase" vs "pre-rulebase"/"post-rulebase").
  const out = [];
  const single = child(scope.element, "rulebase");
  if (single) {
    const rules = child(child(single, "security"), "rules");
    if (rules) out.push({ label: `${scope.label} / rulebase`, rulebaseTag: "rulebase", rules });
  }
  for (const tag of ["pre-rulebase", "post-rulebase"]) {
    const rb = child(scope.element, tag);
    if (rb) {
      const rules = child(child(rb, "security"), "rules");
      if (rules) out.push({ label: `${scope.label} / ${tag}`, rulebaseTag: tag, rules });
    }
  }
  return out;
}

function parseRuleEntry(entryEl) {
  return {
    name: entryName(entryEl),
    disabled: textOf(child(entryEl, "disabled")) === "yes",
    action: textOf(child(entryEl, "action")) || "allow",
    from: memberList(child(entryEl, "from")),
    to: memberList(child(entryEl, "to")),
    source: memberList(child(entryEl, "source")),
    destination: memberList(child(entryEl, "destination")),
    application: memberList(child(entryEl, "application")),
    service: memberList(child(entryEl, "service")),
    category: memberList(child(entryEl, "category")),
    logEnd: textOf(child(entryEl, "log-end")),
    logStart: textOf(child(entryEl, "log-start")),
    hasProfileSetting: !!child(entryEl, "profile-setting"),
    tags: memberList(child(entryEl, "tag")),
    description: textOf(child(entryEl, "description")),
  };
}

// ---------- main entry point ----------

export function runAudit(configEl) {
  const { sharedScope, scopes, deviceEntryName } = buildScopeTree(configEl);

  const allScopes = new Map();
  allScopes.set(sharedScope.id, sharedScope);
  for (const scope of scopes) {
    for (const s of scopeChain(scope)) allScopes.set(s.id, s);
  }

  const objectsByScope = new Map();
  for (const scope of allScopes.values()) {
    objectsByScope.set(scope.id, collectObjectsInScope(scope));
  }

  const disabledRules = [];
  const bestPractice = [];
  const overlyOpenRules = [];
  const usedObjectKeys = new Set(); // `${scope.id}::${kind}::${name}`
  const rulebaseGroups = []; // for shadow detection, grouped by ordered rulebase

  for (const scope of scopes) {
    const chain = scopeChain(scope);

    // Rulebases visible to this scope: its own (pre/post/rulebase) plus, for
    // device-groups, shared's pre/post-rulebase (Panorama pushes shared
    // rules into every device-group's effective policy, pre at the top,
    // post at the bottom).
    const scopesForRulebases = scope.kind === "device-group" ? [scope, sharedScope] : [scope];

    for (const rbScope of scopesForRulebases) {
      for (const rb of collectRulebases(rbScope)) {
        const containerXpath = rulesContainerXpath(deviceEntryName, rbScope, rb.rulebaseTag);
        const ruleEntries = children(rb.rules, "entry").map(parseRuleEntry);
        rulebaseGroups.push({ label: `${scope.label} — ${rb.label}`, rules: ruleEntries });

        for (const rule of ruleEntries) {
          if (rule.disabled) {
            disabledRules.push({ scope: scope.label, rulebase: rb.label, name: rule.name });
          }

          const anyFields = runBestPracticeChecks(rule, scope, rb, bestPractice);
          if (anyFields.length) {
            overlyOpenRules.push({
              scopeLabel: scope.label,
              scopeKind: rbScope.kind,
              scopeName: rbScope.name,
              rulebaseTag: rb.rulebaseTag,
              rulebaseLabel: rb.label,
              containerXpath,
              deviceEntryName,
              anyFields, // which of source/destination/application/service are "any"
              rule,
            });
          }

          // Mark referenced objects as used, resolving group membership
          // recursively (a group can reference other groups/objects).
          markUsed(rule.source, "address", chain, objectsByScope, usedObjectKeys);
          markUsed(rule.destination, "address", chain, objectsByScope, usedObjectKeys);
          markUsed(rule.service, "service", chain, objectsByScope, usedObjectKeys, /*allowAppDefault*/ true);
        }
      }
    }
  }

  const unusedObjects = [];
  const seen = new Set();
  for (const scope of allScopes.values()) {
    const objs = objectsByScope.get(scope.id);
    for (const kind of ["address", "address-group", "service", "service-group"]) {
      for (const name of objs[kind].keys()) {
        const key = `${scope.id}::${kind}::${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (!usedObjectKeys.has(key)) {
          unusedObjects.push({ scope: scope.label, kind, name });
        }
      }
    }
  }

  const possiblyShadowedRules = findPossibleShadows(rulebaseGroups);

  return {
    deviceEntryName,
    summary: {
      scopeCount: scopes.length,
      totalRulesAudited: rulebaseGroups.reduce((n, g) => n + g.rules.length, 0),
      disabledRuleCount: disabledRules.length,
      unusedObjectCount: unusedObjects.length,
      possiblyShadowedCount: possiblyShadowedRules.length,
      bestPracticeFindingCount: bestPractice.length,
      overlyOpenRuleCount: overlyOpenRules.length,
    },
    disabledRules,
    unusedObjects,
    possiblyShadowedRules,
    bestPractice,
    overlyOpenRules,
  };
}

// ---------- helpers ----------

function markUsed(values, kind, chain, objectsByScope, usedSet, allowAppDefault = false) {
  for (const raw of values) {
    if (ANY_KEYWORDS.has(raw)) continue;
    if (allowAppDefault && raw === "application-default") continue;
    resolveAndMark(raw, kind, chain, objectsByScope, usedSet, new Set());
  }
}

function resolveAndMark(name, kind, chain, objectsByScope, usedSet, visiting) {
  if (visiting.has(name)) return; // guard against circular group refs
  visiting.add(name);

  const groupKind = kind === "address" ? "address-group" : "service-group";

  let found = lookupObject(chain, objectsByScope, kind, name);
  if (found) {
    usedSet.add(`${found.scope.id}::${kind}::${name}`);
    return;
  }

  found = lookupObject(chain, objectsByScope, groupKind, name);
  if (found) {
    usedSet.add(`${found.scope.id}::${groupKind}::${name}`);
    const members = memberList(child(found.entry, "static"));
    for (const m of members) {
      resolveAndMark(m, kind, chain, objectsByScope, usedSet, visiting);
    }
    // Dynamic address groups reference objects via tag-match filters, not
    // static members — we can't statically resolve those, so they're
    // conservatively left out of "unused" consideration entirely.
    return;
  }
  // Not found = predefined object (e.g. built-in service/application) or a
  // typo; nothing to mark as used, and we don't flag predefined objects.
}

// Returns the list of match fields (subset of source/destination/application/
// service) that are set to "any" on an allow rule — empty if the rule isn't a
// candidate for optimization. The Policy Optimizer treats a rule as "overly
// open" when ANY one of these fields is "any" (OR), not only when all four are
// (AND) — a single unrestricted field is already worth narrowing.
function runBestPracticeChecks(rule, scope, rb, findings) {
  if (rule.disabled) return []; // don't pile on disabled rules

  const isAny = (arr) => arr.length === 1 && arr[0] === "any";
  const anyFields = ["source", "destination", "application", "service"].filter((f) => isAny(rule[f]));
  const overlyOpen = rule.action === "allow" && anyFields.length > 0;
  if (overlyOpen) {
    const allFour = anyFields.length === 4;
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: allFour
        ? 'Allow rule with any/any/any/any (source, destination, application, service).'
        : `Allow rule with "any" in: ${anyFields.join(", ")}.`,
      severity: allFour ? "high" : "medium",
    });
  }

  if (rule.action === "allow" && !rule.hasProfileSetting) {
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: "Allow rule has no security profile / profile group attached.",
      severity: "medium",
    });
  }

  if (rule.logEnd === "no") {
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: "Log-end explicitly disabled.",
      severity: "low",
    });
  }

  if (rule.tags.length === 0) {
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: "No tags — harder to track ownership/purpose at scale.",
      severity: "info",
    });
  }

  return overlyOpen ? anyFields : [];
}

// Heuristic shadow check: within the same ordered rulebase, does an
// earlier ENABLED rule with the same action fully cover a later rule
// because every one of its match fields is "any"? This intentionally
// under-reports rather than over-reports — it will miss shadows caused by
// overlapping-but-not-equal CIDR ranges or group membership, which require
// IP-range math this v1 doesn't attempt.
function findPossibleShadows(rulebaseGroups) {
  const results = [];
  for (const group of rulebaseGroups) {
    const enabled = group.rules.filter((r) => !r.disabled);
    for (let i = 0; i < enabled.length; i++) {
      const earlier = enabled[i];
      const earlierIsBroad =
        setCovers(earlier.source) &&
        setCovers(earlier.destination) &&
        setCovers(earlier.application) &&
        setCovers(earlier.service);
      if (!earlierIsBroad) continue;
      for (let j = i + 1; j < enabled.length; j++) {
        const later = enabled[j];
        if (later.action === earlier.action) {
          results.push({
            rulebase: group.label,
            shadowingRule: earlier.name,
            shadowedRule: later.name,
            reason: `"${earlier.name}" appears earlier with source/destination/application/service all "any" and the same action ("${earlier.action}") — "${later.name}" may be unreachable.`,
          });
        }
      }
      // Only report the first broad rule's shadow set per rulebase to
      // avoid duplicate noise from multiple broad rules in a row.
      break;
    }
  }
  return results;

  function setCovers(arr) {
    return arr.length === 1 && arr[0] === "any";
  }
}

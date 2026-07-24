# PAN-OS Config Auditor (Chrome extension)

Fetches config from a Palo Alto firewall or Panorama over the PAN-OS XML
API and:

- **Audits** it for disabled rules, unused address/service objects,
  possibly-shadowed rules, and best-practice gaps (overly-open rules,
  missing profiles, logging disabled, untagged rules).
- **Optimizes** overly-open rules — any allow rule with `any` in **one or
  more** of source, destination, application, or service (an OR, not only the
  all-four any/any/any/any case). It pulls **one** PAN-OS Custom Report
  covering all traffic and reuses it for every rule, generating either a
  narrower replacement rule or an app-id backfill, as SET commands and/or a
  direct push to the *candidate* config for you to review and commit.

Everything runs client-side in the extension. Nothing is sent anywhere
except the firewall/Panorama you point it at.

## Load it

1. Go to `chrome://extensions`, enable **Developer mode** (top right).
2. Click **Load unpacked**, select this folder.
3. Click the extension icon → **Open Dashboard** or **Manage Connections**.

## Before you connect

PAN-OS management interfaces almost always present a self-signed (or
internal-CA) certificate. Chrome extensions can't click through a cert
warning the way a regular tab can, so:

1. Open `https://<firewall-or-panorama-ip>` in a normal tab once and accept
   the certificate warning.
2. *Then* add the target on the Connections page.

If you skip this, "Connect & Save" fails with a network error even though
the credentials are correct.

## Firewall/Panorama-side requirements

The account you connect with needs an **Admin Role Profile** with XML API
access for at least: **Configuration** (read running/candidate config, and
write if you'll use the Policy Optimizer's "push to candidate"),
**Operational Requests** (keygen, show system info), and **Report** (the
Policy Optimizer's traffic analysis). Palo Alto's recommended practice is a
dedicated API service account rather than reusing a personal admin login.

## How auth works

1. You enter username + password once on the Connections page.
2. The extension calls `type=keygen` to exchange them for an API key.
3. Only the API key is stored (`chrome.storage.local`); the password is
   discarded immediately after the keygen call.
4. Every subsequent request uses the stored key.
5. Everything (including keygen) is sent as a **POST** with the key/password
   in the request body, not the URL — the first version of this project
   used GET, which puts credentials in browser history and any web-server
   access logs. Fixed.

Chrome prompts you to grant host permission for that specific hostname/IP
the first time you connect (Manifest V3 requires this per-origin, at
runtime — it can't be pre-baked for arbitrary customer firewalls).

## Using the dashboard

1. Toolbar icon → **Open Dashboard**.
2. Pick a saved target and a config source:
   - **Running config** — what's active/effective right now (includes
     Panorama-pushed policy on a managed firewall).
   - **Candidate config** — what's staged but not yet committed. Useful to
     audit your own or someone else's in-progress changes before commit,
     and it's also where the Policy Optimizer's "push" writes to.
3. **Fetch & Audit**, then browse the tabs.
4. **Export Findings (JSON/CSV)** to share the audit results, or
   **Export Raw XML** to download the fetched config and do anything else
   with it yourself outside the extension.

## Policy Optimizer

A rule is flagged as **overly open** when it's an allow rule with `any` in
**one or more** of source, destination, application, or service — a single
unrestricted field is already worth narrowing, so this is an OR, not only the
all-four any/any/any/any case. The Optimizer panel lists every such rule and
shows which fields are `any`.

You run **one** traffic report for the whole firewall (see below) and then,
for each rule, two actions are available:

- **Narrow using report** — rewrites only the fields that were `any` to what
  was actually observed for that rule; fields you'd already scoped are left
  untouched.
- **Add App-ID using report** — leaves source/destination alone, adds the
  observed applications, and switches service to `application-default`.

Both generate a new rule named `<original>-narrowed` or `<original>-appid`
(configurable suffix) rather than editing the original in place, so the old
rule stays until you're confident enough to disable or remove it — the same
approach as the two GUI tools this was ported from.

### One report for the whole firewall

Rather than pulling a separate report per rule, the Optimizer runs a **single**
ad hoc report covering **all** traffic and reuses it for every rule. In the
Optimizer panel:

1. Enter the report container xpath and report name, pick a period/Top N, then
   click **Run traffic report (all rules)** — once.
2. The extension caches the returned rows and enables the **Narrow** / **Add
   App-ID** buttons on every listed rule.
3. Each button filters the cached rows down to that rule (by the report's
   **Rule** column) — no additional report jobs are submitted.

### Setting up a Custom Report (one-time, per firewall/Panorama)

The Optimizer deliberately does **not** guess at PAN-OS's internal summary
database schema — instead it re-runs a report you build once in the GUI, ad
hoc, over all traffic (grouped by rule). To set one up:

1. On the firewall (or Panorama, if reporting on Panorama-visible logs):
   **Monitor → Manage Custom Reports → Add**.
2. Database: **Traffic Log** (or Traffic Summary, depending on version).
3. Columns to include: at minimum **Rule**, **Source Address**, **Destination
   Address**, **Application**, **Service/Port** — these are what the Optimizer
   looks for (it matches column names case-insensitively against a few common
   aliases; see `lib/policyGenerator.js`). The **Rule** column is required: the
   single all-traffic report is attributed back to each rule by rule name.
4. **Group by Rule** (and sort however else you like) so every rule appears in
   the one report — this is what lets a single report cover all rules.
5. Save it with a name you'll remember (e.g. `all-traffic-by-rule`).
6. In the extension's Optimizer panel, enter that name and click
   **List available** to confirm the container xpath is right (defaults to
   `/config/shared/reports`; for a per-vsys report on a firewall use
   `/config/devices/entry/vsys/entry[@name='vsys1']/reports` instead).

The Optimizer then re-runs that exact report definition ad hoc **once**, with
no `(rule eq ...)` filter (so it covers all traffic) and your chosen time
period — so you get PAN-OS's own pre-aggregated numbers, fast, without pulling
raw logs. Per-rule attribution is done client-side from the **Rule** column,
so the same report is reused for every rule instead of one report per rule.

### Pushing changes

**Push new rule to candidate config** calls the config API's `action=set`
against the exact rulebase xpath the audit found the original rule in. It:

- Only ever writes to the **candidate** config — never running, never
  auto-committed. You still commit yourself, from the firewall/Panorama, on
  your own schedule.
- Only **adds** the new suffixed rule — it never touches or deletes the
  original overly-open rule.
- Asks for an explicit confirmation before pushing.

If you'd rather not push via the API at all, copy the generated SET
commands (or download them as `.txt`) and paste them into a CLI session or
Panorama's config-mode terminal yourself — same output, your call on how
it's applied.

## Known limitations (v1)

- Only the **security** rulebase is analyzed — NAT, decryption, QoS,
  authentication rulebases aren't audited yet.
- Panorama **templates** aren't walked (only device-group objects/rules).
- Device-group hierarchy (needed so a child device-group can "see" a
  parent's objects) is read from `/config/readonly/.../parent-dg`. If your
  config export doesn't include that section, every device-group is
  treated as a direct child of Shared — this only affects cross-device-
  group unused-object detection, not per-device-group rule auditing.
- Dynamic address groups (tag-based) can't be resolved statically, so
  their members are never flagged as "unused" — intentional, to avoid
  false positives.
- Shadow detection is a heuristic (same-or-broader `any` fields + same
  action). Treat every "possibly shadowed" result as a lead to check
  manually, not a verdict.
- The Policy Optimizer's report-column matching assumes reasonably standard
  column names (rule/source/destination/application/service). If your report
  uses very different naming, adjust `COLUMN_ALIASES` in
  `lib/policyGenerator.js`.
- The single all-traffic report is attributed back to rules by **rule name**.
  On Panorama, if the same rule name exists in more than one device-group,
  those rows can't be told apart from the report alone — narrow such rules
  with care, or add a device-group column and extend the matching.
- There's no CSV-import fallback in this version (the two GUI tools this
  was ported from supported loading a Traffic Report CSV directly) — the
  live report pull was prioritized since PAN-OS's own summarization is
  faster than client-side CSV parsing. Re-adding a CSV path as an
  alternative input to `summarizeRows()` in `lib/policyGenerator.js` would
  be a small, self-contained addition if you still want it as a fallback
  for environments where Custom Reports aren't practical.

## Architecture notes

- `lib/panApi.js` — XML API client (keygen, running/candidate config,
  set-config, ad hoc report jobs). All POST, all credentials out of the URL.
- `lib/auditEngine.js` — pure config-XML analysis, no UI or network
  dependencies. This is also where rulebase xpaths get computed, since the
  Optimizer needs them to push changes back to the right location.
- `lib/policyGenerator.js` — turns report rows into a suggested rule
  (as SET commands and as pushable XML). No PAN-OS calls in this file.
- `lib/store.js` — `chrome.storage.local` target persistence.
- `lib/navbar.js` — the one place the nav's markup/behavior lives; both
  `dashboard.html` and `options.html` include it with a single
  `<script src="lib/navbar.js" type="module">` tag, so editing the nav
  once updates both pages. It also live-refreshes the target-count badge
  via `chrome.storage.onChanged` — the same mechanism `dashboard.js` and
  `options.js` use to refresh their own target dropdown/list without
  needing a manual reload when a target is added elsewhere.


  ## Todo:
  #Remove todo items if they've already been done
  - Make the app create the report instead of asking for a name of an existing report
  - Make the report automatically filter by rules that can be optimized (either any in src, dst, app, port)

  #Features
  - Delete unused objects, take into account objects that are members of other object groups that could be used in a policy
  - 

// lib/navbar.js
// Injects navbar.html into a page and wires up active-link highlighting
// plus a live target-count badge. Import and call initNavbar() once per
// page (dashboard.js / options.js each do this) — this is the single place
// the nav's markup lives, so editing it once updates every page.

import { getTargets, TARGETS_KEY } from "./store.js";

async function initNavbar() {
  const root = document.getElementById("navbar-root");
  if (!root) return;

  const res = await fetch(chrome.runtime.getURL("navbar.html"));
  root.innerHTML = await res.text();

  const current = location.pathname.split("/").pop();
  root.querySelectorAll("[data-page]").forEach((a) => {
    if (a.dataset.page === current) a.classList.add("active");
  });

  const updateBadge = async () => {
    const badge = document.getElementById("navTargetCount");
    if (!badge) return;
    const targets = await getTargets();
    badge.textContent = `${targets.length} target${targets.length === 1 ? "" : "s"}`;
  };

  await updateBadge();

  // Live refresh: fires whenever chrome.storage.local changes — e.g. you
  // add a firewall on the options page while the dashboard tab is already
  // open. No polling interval needed; this updates the instant storage
  // changes, in every open tab of the extension.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes[TARGETS_KEY]) {
      updateBadge();
    }
  });
}

initNavbar();

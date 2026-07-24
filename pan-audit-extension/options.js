import "./lib/navbar.js";
import { getTargets, upsertTarget, removeTarget, newTargetId, TARGETS_KEY } from "./lib/store.js";
import { baseUrlFor, keygen, getSystemInfo } from "./lib/panApi.js";

const statusEl = document.getElementById("status");

function setStatus(msg, kind) {
  statusEl.textContent = msg;
  statusEl.className = `status ${kind || ""}`;
}

async function renderTargets() {
  const targets = await getTargets();
  const listEl = document.getElementById("targetList");
  listEl.innerHTML = "";
  if (targets.length === 0) {
    listEl.innerHTML = '<div class="meta">No saved targets yet.</div>';
    return;
  }
  for (const t of targets) {
    const row = document.createElement("div");
    row.className = "target";
    row.innerHTML = `
      <div>
        <div><strong>${escapeHtml(t.label || t.host)}</strong></div>
        <div class="meta">${escapeHtml(t.host)}:${t.port} — ${escapeHtml(t.platform || "unknown")} — ${escapeHtml(t.swVersion || "")}</div>
      </div>
    `;
    const removeBtn = document.createElement("button");
    removeBtn.textContent = "Remove";
    removeBtn.className = "secondary";
    removeBtn.style.marginTop = "0";
    removeBtn.addEventListener("click", async () => {
      await removeTarget(t.id);
      renderTargets();
    });
    row.appendChild(removeBtn);
    listEl.appendChild(row);
  }
}

document.getElementById("connectBtn").addEventListener("click", async () => {
  const label = document.getElementById("label").value.trim();
  const host = document.getElementById("host").value.trim();
  const port = parseInt(document.getElementById("port").value.trim() || "443", 10);
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  if (!host || !username || !password) {
    setStatus("Host, username, and password are required.", "error");
    return;
  }

  const origin = `https://${host}/*`;
  setStatus("Requesting permission to contact this host...", "");

  try {
    const granted = await chrome.permissions.request({ origins: [origin] });
    if (!granted) {
      setStatus("Permission was not granted — cannot connect without it.", "error");
      return;
    }

    setStatus("Requesting API key...", "");
    const baseUrl = baseUrlFor({ host, port });
    const apiKey = await keygen(baseUrl, username, password);

    setStatus("Verifying with a system-info call...", "");
    const info = await getSystemInfo(baseUrl, apiKey);

    const target = {
      id: newTargetId(),
      label: label || info.hostname,
      host,
      port,
      apiKey,
      platform: info.isPanorama ? "Panorama" : "Firewall",
      swVersion: info.swVersion,
    };
    await upsertTarget(target);

    document.getElementById("password").value = "";
    setStatus(`Connected to ${info.hostname} (${target.platform}, PAN-OS ${info.swVersion}).`, "ok");
    renderTargets();
  } catch (e) {
    setStatus(e.message, "error");
  }
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

renderTargets();

// Live refresh: reflect targets added/removed from another tab (or this
// page's own writes) immediately, no manual reload needed.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[TARGETS_KEY]) renderTargets();
});

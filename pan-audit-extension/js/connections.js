// js/connections.js
// Pagina de conexiones: cambia usuario/contrasena por una API key via
// keygen y guarda solo la key (store.js). La contrasena nunca se persiste.

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
    listEl.innerHTML = '<div class="meta">Aun no hay conexiones guardadas.</div>';
    return;
  }
  for (const t of targets) {
    const row = document.createElement("div");
    row.className = "target";
    row.innerHTML = `
      <div>
        <div><strong>${escapeHtml(t.label || t.host)}</strong></div>
        <div class="meta">${escapeHtml(t.host)}:${t.port} — ${escapeHtml(t.platform || "desconocido")} — PAN-OS ${escapeHtml(t.swVersion || "?")}</div>
      </div>
    `;
    const removeBtn = document.createElement("button");
    removeBtn.textContent = "Eliminar";
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
  const host = document.getElementById("host").value.trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
  const port = parseInt(document.getElementById("port").value.trim() || "443", 10);
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  if (!host || !username || !password) {
    setStatus("Host, usuario y contrasena son obligatorios.", "error");
    return;
  }

  const origin = `https://${host}/*`;
  setStatus("Solicitando permiso para contactar este host...", "");

  try {
    // IMPORTANTE: permissions.request() debe ejecutarse dentro del gesto del
    // clic, sin ningun await previo — Chrome exige gesto de usuario vivo.
    const granted = await chrome.permissions.request({ origins: [origin] });
    if (!granted) {
      setStatus("Permiso denegado — sin el no se puede conectar.", "error");
      return;
    }

    setStatus("Solicitando API key...", "");
    const baseUrl = baseUrlFor({ host, port });
    const apiKey = await keygen(baseUrl, username, password);

    setStatus("Verificando con 'show system info'...", "");
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
    setStatus(`Conectado a ${info.hostname} (${target.platform}, PAN-OS ${info.swVersion}).`, "ok");
    renderTargets();
  } catch (e) {
    setStatus(e.message, "error");
  }
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

renderTargets();

// Refresco en vivo: refleja conexiones agregadas/eliminadas desde otra
// pestana (o los propios cambios de esta pagina) sin recargar.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[TARGETS_KEY]) renderTargets();
});

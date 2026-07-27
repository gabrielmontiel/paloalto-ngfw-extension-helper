// js/lib/navbar.js
// Inyecta navbar.html en la pagina y activa el resaltado del link actual
// mas el contador de conexiones en vivo. Es el unico lugar donde vive el
// markup de la barra: editarla una vez actualiza todas las paginas.
// (Tomado de pan-audit-extension.)

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
    badge.textContent = `${targets.length} conexion${targets.length === 1 ? "" : "es"}`;
  };

  await updateBadge();

  // Refresco en vivo: se dispara cuando cambia chrome.storage.local — p. ej.
  // agregas un firewall en Conexiones con el dashboard ya abierto en otra
  // pestana. Sin polling; se actualiza al instante en todas las pestanas.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes[TARGETS_KEY]) {
      updateBadge();
    }
  });
}

initNavbar();

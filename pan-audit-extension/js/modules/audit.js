// js/modules/audit.js
// Modulo: auditoria de configuracion (reglas deshabilitadas, objetos sin
// uso, posibles sombras, buenas practicas, tags).
//
// SOLO LECTURA: trae la config (running o candidate) y la analiza en el
// navegador. No hay ninguna llamada de escritura; el candado de panApi.js
// ademas la rechazaria antes de tocar la red.

import { baseUrlFor, getRunningConfig, getCandidateConfig } from "../lib/panApi.js";
import { runAudit } from "../lib/auditEngine.js";

/**
 * @param {object} target  conexion guardada ({host, port, apiKey, label...})
 * @param {"running"|"candidate"} source
 * @param {(mensaje: string, nivel?: string) => void} log
 * @returns {{configEl: Element, result: object}}
 */
export async function ejecutarAuditoria(target, source, log) {
  const baseUrl = baseUrlFor(target);

  log(`${target.host}: descargando configuracion ${source}...`);
  const inicio = Date.now();

  const configEl =
    source === "candidate"
      ? await getCandidateConfig(baseUrl, target.apiKey)
      : await getRunningConfig(baseUrl, target.apiKey);

  const xmlKb = (new XMLSerializer().serializeToString(configEl).length / 1024).toFixed(0);
  log(`${target.host}: configuracion recibida (${xmlKb} KB, ${Date.now() - inicio} ms).`, "ok");

  log("Analizando configuracion (todo el analisis ocurre en tu navegador)...");
  const result = runAudit(configEl, log);

  const s = result.summary;
  log(
    `Auditoria completa: ${s.totalRulesAudited} regla(s) en ${s.scopeCount} ambito(s). ` +
      `${s.disabledRuleCount} deshabilitada(s), ${s.unusedObjectCount} objeto(s) sin uso, ` +
      `${s.possiblyShadowedCount} posible(s) sombra(s), ` +
      `${s.bestPracticeFindingCount} hallazgo(s) de buenas practicas, ` +
      `${s.unusedTagCount} tag(s) sin uso de ${s.tagCount}.`,
    "ok"
  );

  return { configEl, result };
}

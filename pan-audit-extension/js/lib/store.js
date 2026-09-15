// js/lib/store.js
// Persistencia de las conexiones guardadas. Solo se almacenan
// host/puerto/etiqueta/apiKey/plataforma — nunca usuarios ni contrasenas.
// (Tomado de pan-audit-extension.)

export const TARGETS_KEY = "pan_helper_targets";
const KEY = TARGETS_KEY;

export async function getTargets() {
  const data = await chrome.storage.local.get(KEY);
  return data[KEY] || [];
}

export async function saveTargets(targets) {
  await chrome.storage.local.set({ [KEY]: targets });
}

export async function upsertTarget(target) {
  const targets = await getTargets();
  const idx = targets.findIndex((t) => t.id === target.id);
  if (idx >= 0) targets[idx] = target;
  else targets.push(target);
  await saveTargets(targets);
  return targets;
}

export async function removeTarget(id) {
  const targets = (await getTargets()).filter((t) => t.id !== id);
  await saveTargets(targets);
  return targets;
}

export function newTargetId() {
  return `t_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// ---------------------------------------------------------------------------
//  Historial de depuracion por equipo
// ---------------------------------------------------------------------------
// Una entrada por sesion de "Depurar": cuantos objetos habia antes y despues,
// cuantos se eliminaron y con que resultado. Es lo que permite saber cuanto
// se ha depurado en un equipo a lo largo de varias sesiones. Solo cuenta lo
// escrito en la candidate config: si despues se hace revert en la GUI, el
// historial no se entera.

export const HISTORIAL_DEPURACION_KEY = "pan_helper_depuracion_historial";
const MAX_SESIONES_POR_EQUIPO = 100;

async function leerHistoriales() {
  const data = await chrome.storage.local.get(HISTORIAL_DEPURACION_KEY);
  return data[HISTORIAL_DEPURACION_KEY] || {};
}

const HISTORIAL_VACIO = { sesiones: [], totalSesiones: 0, totalEliminados: 0, desde: null };

/**
 * Historial de un equipo: las ultimas sesiones (de la mas antigua a la mas
 * reciente) y los acumulados, que no se pierden al recortar las sesiones
 * viejas.
 */
export async function getHistorialDepuracion(targetId) {
  return { ...HISTORIAL_VACIO, ...((await leerHistoriales())[targetId] || {}) };
}

export async function agregarSesionDepuracion(targetId, sesion) {
  const todos = await leerHistoriales();
  const h = { ...HISTORIAL_VACIO, ...(todos[targetId] || {}) };
  todos[targetId] = {
    sesiones: [...h.sesiones, sesion].slice(-MAX_SESIONES_POR_EQUIPO),
    totalSesiones: h.totalSesiones + 1,
    totalEliminados: h.totalEliminados + (sesion.eliminados || 0),
    desde: h.desde || sesion.fecha,
  };
  await chrome.storage.local.set({ [HISTORIAL_DEPURACION_KEY]: todos });
  return todos[targetId];
}

export async function borrarHistorialDepuracion(targetId) {
  const todos = await leerHistoriales();
  delete todos[targetId];
  await chrome.storage.local.set({ [HISTORIAL_DEPURACION_KEY]: todos });
}

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

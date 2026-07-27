// js/modules/backups.js
// Modulo: backups de configuracion y device-state (de PAN-helper v0.1,
// verificado en produccion), adaptado para usar conexiones guardadas: ya no
// se piden credenciales, cada equipo se consulta con su API key almacenada.
//
// Los archivos van a Descargas/PAN-Helper/AAAA/Mes/DD/ via chrome.downloads.

import { baseUrlFor, exportFile, getSystemInfo } from "../lib/panApi.js";
import { ejecutarEnLote, rutaPorFecha, nombreSeguro, descargarBlob } from "../lib/util.js";

const CARPETA_RAIZ = "PAN-Helper";
const CONCURRENCIA = 4;

/**
 * Procesa un equipo: identifica y descarga los artefactos seleccionados.
 */
async function procesarEquipo(target, opciones, log) {
  const baseUrl = baseUrlFor(target);

  log(`${target.host}: consultando identidad del equipo...`);
  const info = await getSystemInfo(baseUrl, target.apiKey);
  const nombre = nombreSeguro(info.devicename || info.hostname || target.host);
  log(`${target.host}: identificado como ${nombre} (${info.model}, PAN-OS ${info.swVersion}).`);

  const archivos = [];

  if (opciones.incluirConfig) {
    log(`${nombre}: descargando configuracion...`);
    const blob = await exportFile(baseUrl, target.apiKey, "configuration");
    const ruta = `${opciones.carpeta}/PA-backup_${nombre}.xml`;
    await descargarBlob(blob, ruta);
    archivos.push(ruta);
    log(`${nombre}: configuracion lista (${(blob.size / 1024).toFixed(0)} KB) -> ${ruta}`, "ok");
  }

  if (opciones.incluirDeviceState) {
    log(`${nombre}: descargando device-state (puede tardar varios minutos)...`);
    const blob = await exportFile(baseUrl, target.apiKey, "device-state");
    const ruta = `${opciones.carpeta}/PA-DeviceState_${nombre}.tgz`;
    await descargarBlob(blob, ruta);
    archivos.push(ruta);
    log(`${nombre}: device-state listo (${(blob.size / 1024 / 1024).toFixed(1)} MB) -> ${ruta}`, "ok");
  }

  return { nombre, info, archivos };
}

/**
 * Punto de entrada del modulo.
 *
 * @param {{targets: object[], incluirConfig: boolean, incluirDeviceState: boolean}} config
 *        `targets` son conexiones guardadas (con apiKey), no credenciales.
 * @param {(mensaje: string, nivel?: string) => void} log
 * @param {(hechos: number, total: number) => void} onProgreso
 */
export async function ejecutarBackups(config, log, onProgreso) {
  const { targets, incluirConfig, incluirDeviceState } = config;

  const carpeta = `${CARPETA_RAIZ}/${rutaPorFecha()}`;
  log(`Destino: Descargas/${carpeta}`);
  log(`${targets.length} equipo(s), hasta ${CONCURRENCIA} en paralelo.`);

  let hechos = 0;

  const resultados = await ejecutarEnLote(targets, CONCURRENCIA, async (target) => {
    try {
      return await procesarEquipo(target, { carpeta, incluirConfig, incluirDeviceState }, log);
    } finally {
      onProgreso(++hechos, targets.length);
    }
  });

  const exitosos = resultados.filter((r) => r.ok);
  const fallidos = resultados.filter((r) => !r.ok);

  for (const f of fallidos) {
    log(`${f.item.host}: ${f.error.message}`, "error");
  }

  log(
    `Backups finalizados. ${exitosos.length} exitoso(s), ${fallidos.length} con error.`,
    fallidos.length ? "warn" : "ok"
  );

  return { exitosos, fallidos };
}

// js/lib/util.js
// Utilidades compartidas por los modulos: concurrencia limitada, rutas por
// fecha, CSV y descargas via chrome.downloads. (Consolidado de panos.js y
// de los modulos de PAN-helper v0.1.)

/**
 * Ejecuta tareas con concurrencia limitada. Equivale al ThreadPoolExecutor
 * de los scripts de Python, pero sin saturar al equipo ni al navegador.
 *
 * @param {Array} items
 * @param {number} limite  tareas simultaneas
 * @param {(item, indice) => Promise} tarea
 * @returns {Promise<Array<{ok: boolean, item: any, valor?: any, error?: Error}>>}
 */
export async function ejecutarEnLote(items, limite, tarea) {
  const resultados = new Array(items.length);
  let siguiente = 0;

  async function trabajador() {
    while (siguiente < items.length) {
      const i = siguiente++;
      try {
        resultados[i] = { ok: true, item: items[i], valor: await tarea(items[i], i) };
      } catch (error) {
        resultados[i] = { ok: false, item: items[i], error };
      }
    }
  }

  const trabajadores = Array.from(
    { length: Math.min(limite, items.length) },
    trabajador
  );
  await Promise.all(trabajadores);

  return resultados;
}

/**
 * Ruta de carpeta por fecha: 2026/Julio/24
 * chrome.downloads crea los subdirectorios automaticamente dentro de la
 * carpeta de Descargas.
 */
export function rutaPorFecha() {
  const meses = [
    "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
    "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre",
  ];
  const hoy = new Date();
  return `${hoy.getFullYear()}/${meses[hoy.getMonth()]}/${hoy.getDate()}`;
}

/** Quita caracteres que chrome.downloads rechaza en nombres de archivo. */
export function nombreSeguro(texto) {
  return String(texto).replace(/[<>:"/\\|?*\x00-\x1f]/g, "_").trim() || "desconocido";
}

/** Convierte una lista de objetos planos a CSV (columnas de la primera fila). */
export function aCsv(filas) {
  if (!filas.length) return "";

  const columnas = Object.keys(filas[0]);
  const escapar = (v) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };

  return [
    columnas.join(","),
    ...filas.map((f) => columnas.map((c) => escapar(f[c])).join(",")),
  ].join("\r\n");
}

/**
 * Descarga un blob a Descargas/<rutaRelativa> via chrome.downloads.
 * chrome.downloads crea los subdirectorios que hagan falta.
 */
export async function descargarBlob(blob, rutaRelativa, conflictAction = "overwrite") {
  const url = URL.createObjectURL(blob);

  try {
    const id = await chrome.downloads.download({
      url,
      filename: rutaRelativa,
      conflictAction,
      saveAs: false,
    });

    if (id === undefined) {
      // download() resuelve con undefined cuando la descarga fue rechazada;
      // el motivo queda en runtime.lastError.
      const motivo = chrome.runtime.lastError?.message || "motivo no reportado";
      throw new Error(`Chrome rechazo la descarga de '${rutaRelativa}': ${motivo}`);
    }

    return id;
  } finally {
    // Se revoca con retraso: revocarla de inmediato corta la descarga.
    setTimeout(() => URL.revokeObjectURL(url), 120_000);
  }
}

/** Descarga texto (CSV/JSON/XML) a Descargas/<rutaRelativa>. */
export async function descargarTexto(texto, rutaRelativa, mime = "text/csv;charset=utf-8") {
  // BOM para que Excel abra los CSV en UTF-8 sin romper acentos.
  const contenido = mime.startsWith("text/csv") ? "﻿" + texto : texto;
  const blob = new Blob([contenido], { type: mime });
  return descargarBlob(blob, rutaRelativa, "uniquify");
}

// ---------------------------------------------------------------------------
//  CSV de entrada (lista de politicas para hardening)
// ---------------------------------------------------------------------------

/**
 * Parser CSV minimo con soporte de comillas dobles y "" escapadas.
 * Suficiente para los CSV exportados desde la GUI de Palo Alto.
 */
export function parsearCsv(texto) {
  const filas = [];
  let fila = [];
  let campo = "";
  let enComillas = false;

  // Se normalizan los saltos de linea para no depender del origen del archivo.
  const t = texto.replace(/^﻿/, "").replace(/\r\n?/g, "\n");

  for (let i = 0; i < t.length; i++) {
    const c = t[i];

    if (enComillas) {
      if (c === '"') {
        if (t[i + 1] === '"') { campo += '"'; i++; }
        else enComillas = false;
      } else campo += c;

    } else if (c === '"') {
      enComillas = true;
    } else if (c === ",") {
      fila.push(campo); campo = "";
    } else if (c === "\n") {
      fila.push(campo); filas.push(fila); fila = []; campo = "";
    } else {
      campo += c;
    }
  }

  if (campo !== "" || fila.length) { fila.push(campo); filas.push(fila); }

  return filas.filter((f) => f.some((v) => v.trim() !== ""));
}

// Nombres aceptados para la columna de politicas en un CSV cargado.
const COLUMNAS_REGLA = ["rule", "rule name", "rulename", "name"];

/** Extrae la columna de nombres de politica de un CSV. */
export function reglasDesdeCsv(texto) {
  const filas = parsearCsv(texto);
  if (!filas.length) throw new Error("El CSV esta vacio.");

  const cabecera = filas[0].map((c) => c.trim().toLowerCase());
  const indice = cabecera.findIndex((c) => COLUMNAS_REGLA.includes(c));

  if (indice === -1) {
    throw new Error(
      `El CSV no tiene columna de politicas (${COLUMNAS_REGLA.join(", ")}). ` +
        `Columnas encontradas: ${filas[0].join(", ")}`
    );
  }

  const vistos = new Set();
  const reglas = [];

  for (const f of filas.slice(1)) {
    const nombre = (f[indice] || "").trim();
    if (nombre && !vistos.has(nombre)) {
      vistos.add(nombre);
      reglas.push(nombre);
    }
  }

  return reglas;
}

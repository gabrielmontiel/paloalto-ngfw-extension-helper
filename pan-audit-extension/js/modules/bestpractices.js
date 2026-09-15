// js/modules/bestpractices.js
// Modulo: Best Practices (BPA). Port del script Python de BPA original.
//
// Tres origenes, un solo reporte:
//   - json:  un JSON de BPA que ya tienes
//   - scm:   sube el running-config a SCM Posture API y descarga el resultado
//   - local: evalua checks propios sobre el XML, sin salir del navegador
// Todos terminan en el mismo formato best_practices, asi que el resumen, el
// HTML (js/lib/bpaReport.js) y el Excel (js/lib/bpaExcel.js) no dependen del
// origen.
//
// Respecto al firewall es SOLO LECTURA: como mucho descarga la running config
// por panApi.js (con su candado). El origen "scm" si envia la configuracion
// fuera, a la nube de Palo Alto; eso lo hace scmApi.js y solo tras la
// confirmacion explicita del usuario en el formulario.

import { parsearJsonBpa, localizarRaizBpa, resumirBpa, generarHtmlBpa } from "../lib/bpaReport.js";
import { generarExcelBpa, parsearGruposPerfiles } from "../lib/bpaExcel.js";
import { MIME_XLSX } from "../lib/xlsxWriter.js";
import { ejecutarBpaScm } from "../lib/scmApi.js";
import { evaluarConfigLocal } from "../lib/bpaLocal.js";
import { baseUrlFor, getRunningConfig } from "../lib/panApi.js";
import { descargarTexto, descargarBlob, nombreSeguro } from "../lib/util.js";

const CARPETA = "PAN-Helper/best-practices";

function marcaTiempo() {
  return new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
}

function baseArchivo(cliente, marca) {
  return `${CARPETA}/BPA_${nombreSeguro(cliente).replace(/\s+/g, "_")}_${marca}`;
}

const kb = (n) => `${(n / 1024).toFixed(0)} KB`;

// ---------------------------------------------------------------------------
//  running-config.xml
// ---------------------------------------------------------------------------

function parsearXmlConfig(texto, nombre) {
  const doc = new DOMParser().parseFromString(texto, "application/xml");
  if (doc.querySelector("parsererror")) {
    throw new Error(`${nombre} no es XML valido. Usa el running-config.xml sin comprimir.`);
  }
  return doc;
}

/**
 * Panorama o firewall a partir del XML: Panorama tiene device-groups o el
 * nodo <panorama> bajo <config>; un firewall tiene vsys.
 * @returns {"Panorama"|"NGFW"|null}
 */
export function detectarTipoEquipo(doc) {
  const hijos = (el, tag) => (el ? [...el.children].filter((c) => c.tagName === tag) : []);
  const config = elementoConfig(doc);
  if (!config) return null;
  if (hijos(config, "panorama").length) return "Panorama";
  const entradas = hijos(hijos(config, "devices")[0], "entry");
  if (entradas.some((e) => hijos(e, "device-group").length)) return "Panorama";
  if (entradas.some((e) => hijos(e, "vsys").length)) return "NGFW";
  return null;
}

function contarGrupos(grupos, log) {
  const n = Object.keys(grupos).length;
  log(
    n
      ? `${n} Security Profile Group(s) encontrados: ${Object.keys(grupos).slice(0, 8).join(", ")}${n > 8 ? "..." : ""}.`
      : "El XML no tiene <profile-group>: las reglas con grupo seguiran sin resolverse.",
    n ? "ok" : "warn"
  );
  return grupos;
}

/** El elemento <config> de un Document (archivo) o el propio elemento (conexion). */
function elementoConfig(doc) {
  const raiz = doc.documentElement || doc;
  return raiz.tagName === "config" ? raiz : raiz.getElementsByTagName("config")[0] || null;
}

/**
 * Configuracion a evaluar: desde un archivo o descargada del equipo.
 * @returns {Promise<{bytes: Uint8Array, doc: Document|Element, nombre: string}>}
 */
async function obtenerConfig({ fuente, archivoXml, target }, log) {
  if (fuente === "conexion") {
    if (!target) throw new Error("Elige la conexion de la que se descargara la running config.");
    log(`${target.host}: descargando running config...`);
    const inicio = Date.now();
    const configEl = await getRunningConfig(baseUrlFor(target), target.apiKey);
    const texto = `<?xml version="1.0"?>\n${new XMLSerializer().serializeToString(configEl)}`;
    const bytes = new TextEncoder().encode(texto);
    log(`${target.host}: running config recibida (${kb(bytes.length)}, ${Date.now() - inicio} ms).`, "ok");
    return { bytes, doc: configEl, nombre: target.label || target.host };
  }

  if (!archivoXml) throw new Error("Elige el running-config.xml.");
  const bytes = new Uint8Array(await archivoXml.arrayBuffer());
  if (!bytes.length) throw new Error(`${archivoXml.name} esta vacio.`);
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    throw new Error(`${archivoXml.name} ya esta comprimido (gzip). Usa el .xml sin comprimir.`);
  }
  const doc = parsearXmlConfig(new TextDecoder().decode(bytes), archivoXml.name);
  if (!doc.getElementsByTagName("config").length) {
    throw new Error(
      `${archivoXml.name} no parece un config de PAN-OS (no tiene <config>). Exportalo desde ` +
        "Device > Setup > Operations > Export named configuration snapshot."
    );
  }
  log(`${archivoXml.name}: ${kb(bytes.length)}, XML valido.`, "ok");
  return { bytes, doc, nombre: archivoXml.name };
}

// ---------------------------------------------------------------------------
//  Cierre comun: resumen + descargas
// ---------------------------------------------------------------------------

async function finalizar(data, { cliente, grupos, descargarHtml, descargarExcel, jsonCrudo }, log) {
  const nombreCliente = (cliente || "").trim() || "Cliente";
  const resumen = resumirBpa(data);
  const k = resumen.kpis;

  log(
    `BPA: ${resumen.dispositivo.tipo}, ${resumen.filas.length} check(s) evaluados, ` +
      `${k.aplicables} aplicables, ${resumen.hallazgos.length} hallazgo(s) distintos. ` +
      `Cumplimiento ${k.pctCumplimiento.toFixed(1)}%.`,
    "ok"
  );
  if (resumen.faltaAdoption && !resumen.local) {
    log(
      "El reporte no trae adoption/adoption_summary: no afecta los checks; en el Excel, Reglas, " +
        "Adopcion y BP Mode se reconstruyen desde la configuracion de las reglas.",
      "warn"
    );
  }

  const resultado = { resumen, data, grupos, cliente: nombreCliente, marca: marcaTiempo() };
  resultado.html = generarHtmlBpa(resumen, { cliente: nombreCliente });

  // El JSON de SCM se guarda primero: si algo falla despues, no hay que
  // volver a subir la configuracion para recuperarlo.
  if (jsonCrudo) {
    const ruta = `${baseArchivo(nombreCliente, resultado.marca)}.json`;
    await descargarTexto(JSON.stringify(jsonCrudo, null, 2), ruta, "application/json");
    log(`JSON del BPA en Descargas/${ruta}`, "ok");
  }
  if (descargarHtml) await descargarReporteHtml(resultado, log);
  if (descargarExcel) await descargarReporteExcel(resultado, log);

  return resultado;
}

// ---------------------------------------------------------------------------
//  Origenes
// ---------------------------------------------------------------------------

/**
 * Origen "json": procesa un JSON de BPA existente.
 *
 * La configuracion del equipo es opcional: el JSON del BPA no trae la
 * definicion de los Security Profile Groups y, sin ella, las reglas que usan
 * grupos quedan fuera de 'Habilitado' / 'En BP Mode' en el Excel.
 *
 * @param {object}  opciones
 * @param {File}    opciones.archivo       JSON del BPA
 * @param {"ninguna"|"conexion"|"archivo"} [opciones.fuente]
 * @param {object}  [opciones.target]      conexion guardada (fuente "conexion")
 * @param {File}    [opciones.archivoXml]  running-config.xml (fuente "archivo")
 * @param {string}  opciones.cliente
 * @param {boolean} opciones.descargarHtml
 * @param {boolean} opciones.descargarExcel
 */
export async function procesarJsonBpa({ archivo, fuente = "ninguna", target, archivoXml, cliente, descargarHtml, descargarExcel }, log) {
  if (!archivo) throw new Error("Elige el archivo JSON del BPA.");
  log(`Leyendo ${archivo.name} (${kb(archivo.size)})...`);
  const data = parsearJsonBpa(await archivo.text());

  let grupos = null;
  if (fuente !== "ninguna") {
    const { doc } = await obtenerConfig({ fuente, target, archivoXml }, log);
    log("Resolviendo Security Profile Groups con la configuracion del equipo...");
    grupos = contarGrupos(parsearGruposPerfiles(elementoConfig(doc)), log);
  }
  return finalizar(data, { cliente, grupos, descargarHtml, descargarExcel }, log);
}

/**
 * Origen "scm": sube la configuracion a Strata Cloud Manager y procesa el
 * resultado. Las credenciales se usan y se descartan; no se guardan.
 *
 * @param {object}  opciones
 * @param {"conexion"|"archivo"} opciones.fuente
 * @param {object}  [opciones.target]      conexion guardada (fuente "conexion")
 * @param {File}    [opciones.archivoXml]  running-config.xml (fuente "archivo")
 * @param {"auto"|"NGFW"|"Panorama"} opciones.tipoEquipo
 * @param {string}  opciones.modelo
 * @param {string}  opciones.clientId
 * @param {string}  opciones.clientSecret
 * @param {boolean} opciones.borrarAlTerminar
 * @param {boolean} opciones.guardarJson
 * @param {string}  opciones.cliente
 * @param {boolean} opciones.descargarHtml
 * @param {boolean} opciones.descargarExcel
 * @param {(texto: string) => void} [progreso]
 */
export async function procesarScmBpa(opciones, log, progreso) {
  const { bytes, doc, nombre } = await obtenerConfig(opciones, log);

  const detectado = detectarTipoEquipo(doc);
  let deviceType = opciones.tipoEquipo;
  if (deviceType === "auto") {
    deviceType = detectado || (/panorama/i.test(opciones.target?.platform || "") ? "Panorama" : "NGFW");
    log(`Tipo de equipo: ${deviceType}${detectado ? " (detectado en el XML)" : " (no se pudo detectar en el XML; se asume)"}.`);
  } else if (detectado && detectado !== deviceType) {
    log(`Aviso: elegiste ${deviceType}, pero el XML parece de ${detectado}. Si el BPA falla, revisa el tipo de equipo.`, "warn");
  }

  // Los grupos salen del mismo XML que se sube: no hace falta cargarlo aparte.
  const grupos = contarGrupos(parsearGruposPerfiles(doc), log);

  log(`Enviando ${nombre} a Strata Cloud Manager (la configuracion sale de tu equipo hacia Palo Alto).`, "warn");
  const { reporte, id } = await ejecutarBpaScm(
    {
      clientId: opciones.clientId.trim(),
      clientSecret: opciones.clientSecret,
      xmlBytes: bytes,
      deviceType,
      model: (opciones.modelo || "").trim() || "PA-5220",
      borrarAlTerminar: opciones.borrarAlTerminar,
    },
    log,
    progreso
  );

  const data = localizarRaizBpa(reporte);
  if (!data) {
    const claves = reporte && typeof reporte === "object" ? Object.keys(reporte).join(", ") : typeof reporte;
    throw new Error(`El reporte ${id} no contiene 'best_practices'. Claves recibidas: ${claves}.`);
  }

  return finalizar(
    data,
    {
      cliente: opciones.cliente || opciones.target?.label,
      grupos,
      descargarHtml: opciones.descargarHtml,
      descargarExcel: opciones.descargarExcel,
      jsonCrudo: opciones.guardarJson ? reporte : null,
    },
    log
  );
}

/**
 * Origen "local": evalua los checks de PAN Helper sobre la configuracion, sin
 * enviarla a ningun lado.
 *
 * @param {object}  opciones
 * @param {"conexion"|"archivo"} opciones.fuente
 * @param {object}  [opciones.target]
 * @param {File}    [opciones.archivoXml]
 * @param {string}  opciones.cliente
 * @param {boolean} opciones.descargarHtml
 * @param {boolean} opciones.descargarExcel
 */
export async function procesarLocalBpa(opciones, log) {
  const { doc, nombre } = await obtenerConfig(opciones, log);
  const config = elementoConfig(doc);
  if (!config) throw new Error(`${nombre} no tiene un elemento <config>.`);

  log("Evaluando buenas practicas en tu navegador (la configuracion no sale del equipo)...");
  const data = evaluarConfigLocal(config, {}, log);
  const grupos = contarGrupos(parsearGruposPerfiles(config), log);

  return finalizar(
    data,
    {
      cliente: opciones.cliente || opciones.target?.label,
      grupos,
      descargarHtml: opciones.descargarHtml,
      descargarExcel: opciones.descargarExcel,
    },
    log
  );
}

// ---------------------------------------------------------------------------
//  Descargas
// ---------------------------------------------------------------------------

/** Descarga el HTML a Descargas/PAN-Helper/best-practices/. */
export async function descargarReporteHtml({ html, cliente, marca }, log) {
  const ruta = `${baseArchivo(cliente, marca)}.html`;
  await descargarTexto(html, ruta, "text/html;charset=utf-8");
  log(`Reporte HTML en Descargas/${ruta}`, "ok");
  return ruta;
}

/** Genera y descarga el Excel a Descargas/PAN-Helper/best-practices/. */
export async function descargarReporteExcel({ data, grupos, cliente, marca }, log) {
  const inicio = Date.now();
  const { bytes, checks, hallazgos, reconstruido } = generarExcelBpa(data, { cliente, grupos });
  const ruta = `${baseArchivo(cliente, marca)}.xlsx`;
  await descargarBlob(new Blob([bytes], { type: MIME_XLSX }), ruta, "uniquify");
  log(
    `Excel en Descargas/${ruta} (${kb(bytes.length)}, ${checks} checks, ` +
      `${hallazgos} hallazgos distintos${reconstruido ? ", adopcion reconstruida" : ""}, ${Date.now() - inicio} ms).`,
    "ok"
  );
  return ruta;
}

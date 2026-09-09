// js/modules/certificados.js
// Modulo: control de vencimiento de certificados.
// Port de control-vencimiento-certificados/ (variantes FW-StandAlone y Panorama).
//
// Firewall: 'request certificate show' devuelve los certificados compartidos.
// Si el equipo es multi-vsys, se repite la consulta acotada a cada vsys.
// Panorama: los certificados viven en la configuracion de cada template, mas
// los del propio Panorama en /config/shared/certificate.
//
// SOLO LECTURA: 'show system info', el comando de certificados y
// config action=get. El candado de panApi.js no necesita excepciones.
//
// Tres errores del script original, corregidos aqui:
//
//  1. Los certificados YA VENCIDOS se descartaban (`if fecha < hoy: continue`).
//     Son justo lo mas urgente de un informe, asi que aqui tienen su propio
//     grupo y encabezan la tabla.
//  2. Doble conteo: la cadena `if <30 ... if (>30 y <90) ... else` colgaba el
//     else del segundo if, asi que todo lo urgente aparecia tambien en la
//     tabla de "mas de 3 meses". Aqui la clasificacion es excluyente.
//  3. El nombre del certificado se recuperaba con `fechas.index(fecha)`, que
//     devuelve la primera coincidencia: dos certificados con la misma fecha
//     mostraban el mismo nombre. Aqui cada certificado viaja como un objeto.

import {
  baseUrlFor,
  getSystemInfo,
  op,
  getConfig,
  listarNombres,
} from "../lib/panApi.js";
import { ejecutarEnLote, aCsv, descargarTexto, nombreSeguro } from "../lib/util.js";

const CONCURRENCIA = 4;
const CARPETA_RAIZ = "PAN-Helper";
const MS_POR_DIA = 24 * 60 * 60 * 1000;

const CMD_CERTIFICADOS = "<request><certificate><show></show></certificate></request>";

// Orden de urgencia: es tambien el orden en que se presentan.
export const ESTADOS = ["vencido", "critico", "proximo", "vigente"];

// ---------------------------------------------------------------------------
//  Parseo y clasificacion
// ---------------------------------------------------------------------------

const MESES = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

/**
 * PAN-OS devuelve las fechas como "Jan 15 12:00:00 2027 GMT". Se intenta
 * primero el parser del navegador y se cae a uno explicito, porque el
 * formato no es ISO y no todos los motores lo aceptan igual.
 *
 * @returns {Date|null}
 */
export function parsearFechaCertificado(texto) {
  const s = String(texto || "").trim();
  if (!s) return null;

  const m = s.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})/);
  if (m) {
    const mes = MESES[m[1].toLowerCase()];
    if (mes !== undefined) {
      // Las fechas de PAN-OS vienen en GMT.
      return new Date(Date.UTC(+m[6], mes, +m[2], +m[3], +m[4], +m[5]));
    }
  }

  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Dias entre hoy y la fecha dada. Negativo = ya vencio. */
export function diasHasta(fecha, ahora = new Date()) {
  return Math.floor((fecha.getTime() - ahora.getTime()) / MS_POR_DIA);
}

/**
 * Clasificacion EXCLUYENTE: cada certificado cae en un solo grupo.
 * El script original solapaba los rangos y duplicaba filas.
 */
export function clasificar(dias, umbralCritico = 30, umbralProximo = 90) {
  if (dias < 0) return "vencido";
  if (dias < umbralCritico) return "critico";
  if (dias < umbralProximo) return "proximo";
  return "vigente";
}

/**
 * El issuer viene como "C=US, O=Acme, CN=Acme Root CA". Interesa el CN.
 * El original hacia split(", ")[-1].split("=")[1], que revienta si el ultimo
 * componente no lleva "=" y falla si el CN no es el ultimo.
 */
export function cnDeIssuer(issuer) {
  const s = String(issuer || "").trim();
  if (!s) return "";
  const cn = s.match(/(?:^|,)\s*CN\s*=\s*([^,]+)/i);
  return cn ? cn[1].trim() : s;
}

/** Certificados de una respuesta, ya normalizados. */
function leerCertificados(result, ambito) {
  if (!result) return [];

  return Array.from(result.querySelectorAll("entry"))
    .map((e) => {
      const nombre = e.getAttribute("name");
      const texto = (tag) => e.querySelector(tag)?.textContent?.trim() || "";
      const expira = texto("not-valid-after");
      if (!nombre || !expira) return null;
      return {
        ambito,
        nombre,
        expiraTexto: expira,
        emisor: cnDeIssuer(texto("issuer")),
        asunto: texto("subject"),
      };
    })
    .filter(Boolean);
}

// ---------------------------------------------------------------------------
//  Consulta por plataforma
// ---------------------------------------------------------------------------

async function certificadosDeFirewall(baseUrl, apiKey, info, log) {
  const certificados = [];

  // Compartidos: presentes tanto en single-vsys como en multi-vsys.
  const compartidos = await op(baseUrl, apiKey, CMD_CERTIFICADOS);
  certificados.push(...leerCertificados(compartidos, info.multiVsys ? "shared" : "n/a"));

  if (!info.multiVsys) return certificados;

  const vsysList = await listarNombres(baseUrl, apiKey, "/config/devices/entry/vsys/entry/@name");
  log(`  multi-vsys activo: ${vsysList.length} vsys (${vsysList.join(", ") || "ninguno"}).`, "debug");

  for (const vsys of vsysList) {
    try {
      const res = await op(baseUrl, apiKey, CMD_CERTIFICADOS, { vsys });
      certificados.push(...leerCertificados(res, vsys));
    } catch (e) {
      // Un vsys sin certificados o sin permiso no debe tumbar el equipo entero.
      log(`  ${vsys}: ${e.message}`, "warn");
    }
  }

  return certificados;
}

async function certificadosDePanorama(baseUrl, apiKey, log) {
  const certificados = [];

  // Los del propio Panorama. El script original los omitia.
  try {
    const propios = await getConfig(baseUrl, apiKey, "/config/shared/certificate");
    certificados.push(...leerCertificados(propios, "Panorama (shared)"));
  } catch (e) {
    log(`  certificados propios de Panorama: ${e.message}`, "warn");
  }

  const templates = await listarNombres(
    baseUrl,
    apiKey,
    "/config/devices/entry/template/entry/@name"
  );
  log(`  ${templates.length} template(s): ${templates.join(", ") || "ninguno"}.`, "debug");

  for (const template of templates) {
    const seguro = String(template).replace(/'/g, "");
    try {
      const res = await getConfig(
        baseUrl,
        apiKey,
        `/config/devices/entry/template/entry[@name='${seguro}']/config/shared/certificate`
      );
      certificados.push(...leerCertificados(res, `template ${template}`));
    } catch (e) {
      log(`  template ${template}: ${e.message}`, "warn");
    }
  }

  return certificados;
}

// ---------------------------------------------------------------------------
//  Punto de entrada
// ---------------------------------------------------------------------------

/**
 * @param {{targets: object[], umbralCritico?: number, umbralProximo?: number,
 *          incluirVigentes?: boolean, descargarCsv?: boolean}} config
 * @returns {{filas, resumen, fallidos}}
 */
export async function ejecutarCertificados(config, log, onProgreso) {
  const {
    targets,
    umbralCritico = 30,
    umbralProximo = 90,
    incluirVigentes = true,
    descargarCsv = true,
  } = config;

  if (!targets?.length) {
    throw new Error("Marca al menos un equipo.");
  }

  log(`${targets.length} equipo(s), hasta ${CONCURRENCIA} en paralelo.`);
  log(
    `Umbrales: critico < ${umbralCritico} dias, proximo < ${umbralProximo} dias. ` +
      `Los ya vencidos se reportan aparte.`
  );

  const ahora = new Date();
  let hechos = 0;

  const resultados = await ejecutarEnLote(targets, CONCURRENCIA, async (target) => {
    try {
      const baseUrl = baseUrlFor(target);
      const info = await getSystemInfo(baseUrl, target.apiKey);
      const equipo = info.devicename || info.hostname || target.host;

      log(`${target.host}: ${equipo} (${info.model}, PAN-OS ${info.swVersion}).`, "debug");

      const certificados = info.isPanorama
        ? await certificadosDePanorama(baseUrl, target.apiKey, log)
        : await certificadosDeFirewall(baseUrl, target.apiKey, info, log);

      log(`${equipo}: ${certificados.length} certificado(s).`, certificados.length ? "ok" : "warn");
      return { equipo, plataforma: info.isPanorama ? "Panorama" : "Firewall", certificados };
    } finally {
      onProgreso(++hechos, targets.length);
    }
  });

  // --- consolidacion ---
  const filas = [];
  const fallidos = [];

  resultados.forEach((r, i) => {
    if (!r.ok) {
      fallidos.push({ host: targets[i].host, error: r.error.message });
      log(`${targets[i].host}: ${r.error.message}`, "error");
      return;
    }

    for (const cert of r.valor.certificados) {
      const fecha = parsearFechaCertificado(cert.expiraTexto);
      if (!fecha) {
        log(
          `${r.valor.equipo} / ${cert.nombre}: no se pudo interpretar la fecha ` +
            `'${cert.expiraTexto}'; se reporta sin clasificar.`,
          "warn"
        );
      }

      const dias = fecha ? diasHasta(fecha, ahora) : null;
      const estado = dias === null ? "desconocido" : clasificar(dias, umbralCritico, umbralProximo);

      filas.push({
        Equipo: r.valor.equipo,
        Plataforma: r.valor.plataforma,
        Ambito: cert.ambito,
        Certificado: cert.nombre,
        Expira: cert.expiraTexto,
        "Dias restantes": dias === null ? "" : dias,
        Estado: estado,
        Emisor: cert.emisor,
      });
    }
  });

  const visibles = incluirVigentes ? filas : filas.filter((f) => f.Estado !== "vigente");

  // Orden por urgencia y, dentro de cada grupo, por fecha mas proxima.
  const orden = { vencido: 0, critico: 1, proximo: 2, vigente: 3, desconocido: 4 };
  visibles.sort(
    (a, b) =>
      orden[a.Estado] - orden[b.Estado] ||
      (a["Dias restantes"] === "" ? 1 : a["Dias restantes"]) -
        (b["Dias restantes"] === "" ? 1 : b["Dias restantes"]) ||
      a.Equipo.localeCompare(b.Equipo)
  );

  const resumen = {};
  for (const estado of [...ESTADOS, "desconocido"]) {
    resumen[estado] = filas.filter((f) => f.Estado === estado).length;
  }

  // --- exportacion ---
  if (descargarCsv && visibles.length) {
    const marca = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    const ruta = `${CARPETA_RAIZ}/certificados/Certificados_${nombreSeguro(marca)}.csv`;
    await descargarTexto(aCsv(visibles), ruta);
    log(`CSV en Descargas/${ruta}`, "ok");
  }

  if (resumen.vencido) {
    log(`${resumen.vencido} certificado(s) YA VENCIDOS. Revisar de inmediato.`, "error");
  }
  if (resumen.critico) {
    log(`${resumen.critico} certificado(s) vencen en menos de ${umbralCritico} dias.`, "warn");
  }

  log(
    `Finalizado. ${filas.length} certificado(s) en ${targets.length - fallidos.length} equipo(s)` +
      (fallidos.length ? `, ${fallidos.length} equipo(s) con error.` : "."),
    fallidos.length ? "warn" : "ok"
  );

  return { filas: visibles, resumen, fallidos };
}

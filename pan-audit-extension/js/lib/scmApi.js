// js/lib/scmApi.js
// Cliente de Strata Cloud Manager Posture API para el BPA "config upload".
// Port de la parte API del script Python de BPA original, con la
// tolerancia a variantes de respuesta vista en otras implementaciones.
//
// Flujo: token OAuth -> iniciar upload (id + upload_url firmado) -> PUT del
// XML al bucket -> consultar bpa-result hasta COMPLETED -> bajar el reporte.
//
// Es una capa de red aparte de panApi.js y panRestApi.js: NO habla con el
// firewall, habla con la nube de Palo Alto. Por eso:
//  - Solo toca los hosts de LISTA_HOSTS; cualquier otra URL (incluida una
//    upload_url o report_url inesperada) se rechaza antes de la peticion.
//  - Las credenciales viven solo en memoria mientras dura la operacion; este
//    archivo no escribe nada en chrome.storage.
//  - Nunca registra el secret, el token ni la query de los URL firmados
//    (la firma ES la credencial del bucket).
//  - Comparte la cancelacion del boton rojo (senalDeCancelacion de panApi).

import { senalDeCancelacion, OperacionCanceladaError } from "./panApi.js";
import { localizarRaizBpa } from "./bpaReport.js";

export const TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token";
export const API_HOST = "https://api.sase.paloaltonetworks.com";
const INICIAR_PATH = "/posture/checks/v1/reports/config-file-upload";
const RESULTADO_PATH = (id) => `/posture/checks/v1/reports/${encodeURIComponent(id)}/bpa-result`;

// Origenes que la extension pide al usuario antes de usar SCM. El upload_url
// y el report_url son URL firmados de Google Cloud Storage.
export const ORIGENES_SCM = [
  "https://auth.apps.paloaltonetworks.com/*",
  "https://api.sase.paloaltonetworks.com/*",
  "https://storage.googleapis.com/*",
  "https://*.storage.googleapis.com/*",
];

const LISTA_HOSTS = [
  /^auth\.apps\.paloaltonetworks\.com$/,
  /^api\.sase\.paloaltonetworks\.com$/,
  /^storage\.googleapis\.com$/,
  /^[a-z0-9._-]+\.storage\.googleapis\.com$/,
];

const ESTADOS_ACTIVOS = new Set([
  "", "UPLOAD_PENDING", "UPLOAD_COMPLETE", "QUEUED", "PENDING", "SCHEDULED",
  "STARTING", "RUNNING", "IN_PROGRESS", "PROCESSING", "ACCEPTED",
]);
const ESTADOS_OK = new Set(["COMPLETED", "SUCCESS", "SUCCEEDED"]);
const ESTADOS_FALLO = new Set(["FAILED", "ERROR", "CANCELLED", "CANCELED"]);

// ---------------------------------------------------------------------------
//  Utilidades
// ---------------------------------------------------------------------------

let logger = () => {};

/** El dashboard instala aqui su consola (nivel "debug" para el detalle). */
export function setScmLogger(fn) {
  logger = fn || (() => {});
}

/** URL para registro: host + ruta, sin la query (en un URL firmado es la credencial). */
function urlParaLog(url) {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}${u.search ? "?…" : ""}`;
  } catch {
    return "(url invalida)";
  }
}

/** Rechaza cualquier URL fuera de la lista de hosts, antes de tocar la red. */
export function verificarUrlScm(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new Error("SCM devolvio una URL invalida; no se usara.");
  }
  if (u.protocol !== "https:" || !LISTA_HOSTS.some((re) => re.test(u.hostname))) {
    throw new Error(
      `Peticion bloqueada: ${u.protocol}//${u.hostname} no es un host de Strata Cloud Manager ` +
        "ni de su almacenamiento. Si Palo Alto cambio de dominio, hay que actualizar scmApi.js."
    );
  }
  return u;
}

function esperar(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new OperacionCanceladaError());
    const t = setTimeout(() => {
      signal.removeEventListener("abort", alAbortar);
      resolve();
    }, ms);
    const alAbortar = () => {
      clearTimeout(t);
      reject(new OperacionCanceladaError());
    };
    signal.addEventListener("abort", alAbortar, { once: true });
  });
}

/**
 * Quita de un texto destinado al log lo que puede ser credencial: la query de
 * cualquier URL (firma del bucket), tokens y secrets en JSON o form-encoded.
 */
export function redactarSecretos(texto) {
  return String(texto ?? "")
    .replace(/(https?:\/\/[^\s"'<>?]+)\?[^\s"'<>]*/gi, "$1?…")
    .replace(/("?(?:access_token|refresh_token|id_token|client_secret|token|signature)"?\s*[:=]\s*"?)[^"&\s,}]+/gi, "$1…")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1…");
}

async function textoSeguro(resp) {
  try {
    return redactarSecretos((await resp.text()).slice(0, 500));
  } catch {
    return "";
  }
}

/** El token de SCM solo viaja a la API; nunca al almacenamiento ni a otro host. */
function esHostApi(url) {
  return new URL(url).host === new URL(API_HOST).host;
}

async function peticion(url, opciones, signal) {
  verificarUrlScm(url);
  if (signal.aborted) throw new OperacionCanceladaError();
  logger(`SCM ${opciones.method || "GET"} ${urlParaLog(url)}`, "debug");
  try {
    // redirect "error": una redireccion podria sacar la peticion (con su
    // token o la configuracion) fuera de LISTA_HOSTS sin pasar el filtro.
    return await fetch(url, { ...opciones, signal, credentials: "omit", cache: "no-store", redirect: "error" });
  } catch (e) {
    if (e?.name === "AbortError" || signal.aborted) throw new OperacionCanceladaError();
    throw new Error(
      `No se pudo conectar con ${new URL(url).host}: ${redactarSecretos(e.message)}. Revisa la salida a internet ` +
        "y que hayas concedido el permiso de acceso a Strata Cloud Manager (o SCM respondio con una redireccion, que se bloquea)."
    );
  }
}

const UUID = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/;

// ---------------------------------------------------------------------------
//  Pasos del flujo
// ---------------------------------------------------------------------------

/** Paso 1: token OAuth (client credentials). Dura ~15 minutos. */
export async function obtenerToken({ clientId, clientSecret }, signal) {
  if (!clientId || !clientSecret) throw new Error("Faltan el Client ID o el Client Secret de SCM.");
  const cuerpo = new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret });
  const resp = await peticion(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: cuerpo,
  }, signal);

  if (!resp.ok) {
    const detalle = await textoSeguro(resp);
    if (resp.status === 400 || resp.status === 401) {
      throw new Error(`SCM rechazo las credenciales (${resp.status}). Revisa el Client ID y el Client Secret del service account. ${detalle}`);
    }
    throw new Error(`Fallo al pedir el token a SCM (${resp.status}): ${detalle}`);
  }
  const token = (await resp.json().catch(() => ({}))).access_token;
  if (!token) throw new Error("SCM respondio sin access_token.");
  return token;
}

/** Paso 2: inicia el upload. Devuelve {id, uploadUrl}. */
export async function iniciarUpload(token, { deviceType, model, borrarAlTerminar }, signal) {
  const resp = await peticion(API_HOST + INICIAR_PATH, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ device_type: deviceType, model, delete_after_processing: Boolean(borrarAlTerminar) }),
  }, signal);

  if (!resp.ok) {
    throw new Error(`SCM no acepto iniciar el upload (${resp.status}): ${await textoSeguro(resp)}`);
  }
  const cuerpo = await resp.json().catch(() => ({}));
  const uploadUrl = cuerpo.upload_url || cuerpo["upload-url"] || cuerpo.data?.upload_url;
  const crudo = cuerpo.id || cuerpo.task_id || cuerpo.report_id || cuerpo.data?.id || resp.headers.get("Location") || "";
  const id = (UUID.exec(String(crudo)) || [String(crudo)])[0];
  if (!uploadUrl || !id) {
    throw new Error(`SCM respondio sin upload_url o id. Claves recibidas: ${Object.keys(cuerpo).join(", ") || "(ninguna)"}.`);
  }
  verificarUrlScm(uploadUrl);
  return { id, uploadUrl };
}

/**
 * Paso 3: sube el XML SIN comprimir, pero con "Content-Encoding: gzip".
 * La documentacion pide gzip, pero hoy el endpoint espera el XML crudo y la
 * firma del URL incluye ese header (si se manda gzip real, el BPA termina en
 * FAILED). Ver https://github.com/PaloAltoNetworks/pan.dev/issues/1327
 * Si Palo Alto lo corrige y el PUT empieza a fallar, probar sin el header.
 */
export async function subirConfig(uploadUrl, xmlBytes, signal) {
  const resp = await peticion(uploadUrl, {
    method: "PUT",
    headers: { "Content-Type": "text/plain", "Content-Encoding": "gzip" },
    body: xmlBytes,
  }, signal);
  if (!resp.ok) {
    throw new Error(`El almacenamiento de SCM rechazo la subida (${resp.status}): ${await textoSeguro(resp)}`);
  }
}

/** Estado de una respuesta de bpa-result, tolerando las variantes vistas. */
export function estadoDe(cuerpo) {
  return String(cuerpo?.status ?? cuerpo?.data?.status ?? cuerpo?.result?.status ?? "").toUpperCase();
}

/** URL del reporte dentro de la respuesta, donde sea que venga. */
export function buscarUrlReporte(obj, profundidad = 0) {
  if (profundidad > 6 || obj === null || obj === undefined) return null;
  if (typeof obj === "string") {
    const s = obj.trim();
    return /^https?:\/\//.test(s) ? s : null;
  }
  if (Array.isArray(obj)) {
    for (const v of obj) {
      const u = buscarUrlReporte(v, profundidad + 1);
      if (u) return u;
    }
    return null;
  }
  if (typeof obj === "object") {
    for (const k of ["report_url", "custom_check_url", "download_url", "url", "signed_url", "presigned_url", "href", "location", "link", "result"]) {
      const v = obj[k];
      if (typeof v === "string" && /^https?:\/\//.test(v.trim())) return v.trim();
    }
    for (const v of Object.values(obj)) {
      const u = buscarUrlReporte(v, profundidad + 1);
      if (u) return u;
    }
  }
  return null;
}

async function jsonDesdeBytes(buffer) {
  let bytes = new Uint8Array(buffer);
  // Reporte guardado como .gz sin Content-Encoding: se descomprime aqui.
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const flujo = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    bytes = new Uint8Array(await new Response(flujo).arrayBuffer());
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    throw new Error(`El reporte descargado no es JSON valido: ${e.message}`);
  }
}

/** Paso 5: si el reporte no vino en la respuesta, lo baja del URL indicado. */
export async function obtenerReporte(cuerpo, token, signal) {
  if (localizarRaizBpa(cuerpo)) return cuerpo;
  const url = buscarUrlReporte(cuerpo);
  if (!url) {
    throw new Error(
      "SCM marco el BPA como completado, pero la respuesta no trae el reporte ni un enlace para bajarlo. " +
        `Claves recibidas: ${Object.keys(cuerpo || {}).join(", ")}.`
    );
  }
  let resp = await peticion(url, { method: "GET" }, signal);
  if ((resp.status === 401 || resp.status === 403) && esHostApi(url)) {
    resp = await peticion(url, { method: "GET", headers: { Authorization: `Bearer ${token}` } }, signal);
  }
  if (!resp.ok) throw new Error(`No se pudo descargar el reporte (${resp.status}): ${await textoSeguro(resp)}`);
  return jsonDesdeBytes(await resp.arrayBuffer());
}

// ---------------------------------------------------------------------------
//  Flujo completo
// ---------------------------------------------------------------------------

/**
 * Ejecuta el BPA completo y devuelve el JSON crudo del reporte.
 *
 * La espera no tiene tope (un config grande tarda minutos): termina con
 * COMPLETED, con un estado de fallo, con "Cancelar llamadas", o si SCM deja
 * de reconocer el reporte en 3 consultas seguidas. Si el token vence durante
 * la espera, se renueva con las mismas credenciales (siguen solo en memoria).
 *
 * @param {object} o
 * @param {string} o.clientId
 * @param {string} o.clientSecret
 * @param {Uint8Array} o.xmlBytes
 * @param {"NGFW"|"Panorama"} o.deviceType
 * @param {string} o.model
 * @param {boolean} o.borrarAlTerminar
 * @param {(mensaje: string, nivel?: string) => void} log
 * @param {(texto: string) => void} [progreso]
 * @param {{intervaloInicialMs?: number, intervaloMaxMs?: number, graciaTokenMs?: number}} [tiempos]  (pruebas)
 */
export async function ejecutarBpaScm(o, log, progreso = () => {}, tiempos = {}) {
  // La senal se toma UNA vez: cancelarTodo() instala un controller nuevo y
  // releerla en cada vuelta perderia la cancelacion (ver panApi.js).
  const signal = senalDeCancelacion();
  const intervaloInicial = tiempos.intervaloInicialMs ?? 10_000;
  const intervaloMax = tiempos.intervaloMaxMs ?? 30_000;
  const graciaToken = tiempos.graciaTokenMs ?? 60_000;

  log("SCM: pidiendo token OAuth...");
  let token = await obtenerToken(o, signal);
  let emitido = Date.now();
  log("SCM: token obtenido.", "ok");

  log(`SCM: iniciando upload (device_type=${o.deviceType}, model=${o.model}, borrar al terminar=${o.borrarAlTerminar ? "si" : "no"})...`);
  const { id, uploadUrl } = await iniciarUpload(token, o, signal);
  log(`SCM: reporte ${id} creado.`, "ok");

  log(`SCM: subiendo la configuracion (${(o.xmlBytes.length / 1024).toFixed(0)} KB, sin comprimir)...`);
  await subirConfig(uploadUrl, o.xmlBytes, signal);
  log("SCM: configuracion subida. Esperando el procesamiento; puede tardar varios minutos.", "ok");

  const url = API_HOST + RESULTADO_PATH(id);
  const inicio = Date.now();
  let intervalo = intervaloInicial;
  let ultimoEstado = null;
  let noReconocido = 0;
  let ultimoAviso = 0;

  for (;;) {
    if (signal.aborted) throw new OperacionCanceladaError();
    const reloj = () => {
      const s = Math.floor((Date.now() - inicio) / 1000);
      return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
    };

    let resp;
    try {
      resp = await peticion(url, { method: "GET", headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } }, signal);
    } catch (e) {
      if (e instanceof OperacionCanceladaError) throw e;
      log(`SCM [${reloj()}]: error de red consultando el estado, se reintenta (${e.message})`, "warn");
      await esperar(intervalo, signal);
      continue;
    }

    if (resp.status === 401) {
      // Un token recien emitido que igual da 401 no es vencimiento: es falta
      // de permiso. Sin este tope se renovaria para siempre.
      if (Date.now() - emitido < graciaToken) {
        throw new Error(
          "SCM rechaza la consulta del reporte con un token recien emitido (401). El service account " +
            "probablemente no tiene un rol con acceso a Posture / BPA en ese tenant."
        );
      }
      log(`SCM [${reloj()}]: el token vencio; se renueva y se sigue esperando.`, "warn");
      token = await obtenerToken(o, signal);
      emitido = Date.now();
      continue;
    }

    if (resp.status === 202) {
      progreso(`${reloj()} · ACCEPTED`);
    } else if (!resp.ok) {
      const detalle = await textoSeguro(resp);
      if (resp.status === 404 || resp.status === 400) {
        noReconocido++;
        if (noReconocido >= 3) {
          throw new Error(`SCM dejo de reconocer el reporte ${id} (${resp.status} tres veces seguidas): ${detalle}`);
        }
      }
      log(`SCM [${reloj()}]: la consulta de estado devolvio ${resp.status}; se reintenta. ${detalle}`, "warn");
    } else {
      noReconocido = 0;
      const cuerpo = await resp.json().catch(() => ({}));
      const estado = estadoDe(cuerpo);
      progreso(`${reloj()} · ${estado || "procesando"}`);

      if (ESTADOS_OK.has(estado) || (!estado && localizarRaizBpa(cuerpo))) {
        log(`SCM [${reloj()}]: BPA completado. Descargando el reporte...`, "ok");
        const reporte = await obtenerReporte(cuerpo, token, signal);
        log("SCM: reporte descargado.", "ok");
        return { reporte, id };
      }
      if (ESTADOS_FALLO.has(estado)) {
        throw new Error(
          `SCM marco el BPA como ${estado}. Revisa que sea un running-config completo, en XML sin comprimir, ` +
            `y que el tipo de equipo (${o.deviceType}) sea el correcto. Detalle: ${redactarSecretos(JSON.stringify(cuerpo)).slice(0, 400)}`
        );
      }
      if (!ESTADOS_ACTIVOS.has(estado)) {
        log(`SCM [${reloj()}]: estado no documentado '${estado}'; se trata como en proceso.`, "warn");
      }
      // Cambio de estado: siempre visible. Mismo estado: un aviso por minuto.
      if (estado !== ultimoEstado || Date.now() - ultimoAviso >= 60_000) {
        log(`SCM [${reloj()}]: estado ${estado || "(sin estado)"}`);
        ultimoEstado = estado;
        ultimoAviso = Date.now();
      }
    }

    await esperar(intervalo, signal);
    intervalo = Math.min(intervaloMax, Math.round(intervalo * 1.5));
  }
}

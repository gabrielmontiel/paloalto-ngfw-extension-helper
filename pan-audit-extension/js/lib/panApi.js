// js/lib/panApi.js
// Cliente PAN-OS / Panorama. Mezcla del panApi.js de pan-audit-extension
// (funciones que reciben baseUrl + apiKey, todo por POST) con el candado de
// solo lectura de panos.js de PAN-helper.
//
// SOLO LECTURA — es una garantia de codigo, no una convencion:
//  - verificarSoloLectura() corre en TODAS las rutas de red de este archivo
//    y lanza antes de tocar la red si los parametros describen escritura.
//  - Este archivo no exporta ninguna funcion de escritura (no hay
//    setConfigNode, no hay commit). Es la unica capa de red de la extension.
//
// Credenciales: la contrasena se usa una sola vez en keygen() y nunca se
// persiste; solo se guarda la API key resultante (ver store.js). Todo va por
// POST con la key en el cuerpo, no en la URL (historial, logs de proxy). La
// unica excepcion es exportFile(), que va por GET porque el endpoint de
// export no acepta POST de forma consistente entre versiones de PAN-OS
// (comprobado en produccion por el modulo de backups de PAN-helper v0.1).

import { parseXml, unwrapApiResponse } from "./xmlUtils.js";

// ---------------------------------------------------------------------------
//  Registro detallado: el dashboard instala aqui su consola para que cada
//  llamada a la API quede visible para el usuario (nivel "debug").
// ---------------------------------------------------------------------------

let logger = null;

export function setApiLogger(fn) {
  logger = fn;
}

function trace(mensaje) {
  if (logger) logger(mensaje, "debug");
}

// ---------------------------------------------------------------------------
//  Cancelacion global
//
//  Todas las peticiones de este archivo comparten un AbortController. El
//  boton "Cancelar" del dashboard llama a cancelarTodo(): aborta cualquier
//  llamada al firewall en vuelo (y los polls de logs en espera) y deja un
//  controller nuevo listo para las ejecuciones siguientes.
// ---------------------------------------------------------------------------

let abortController = new AbortController();

export class OperacionCanceladaError extends Error {
  constructor() {
    super("Operacion cancelada por el usuario.");
    this.name = "OperacionCanceladaError";
  }
}

export function cancelarTodo() {
  abortController.abort();
  abortController = new AbortController();
}

function senalActual() {
  return abortController.signal;
}

// Exportada para que otras capas de red de la extension (panRestApi.js)
// compartan la misma cancelacion del boton rojo.
export function senalDeCancelacion() {
  return abortController.signal;
}

function traducirAbort(e) {
  return e?.name === "AbortError" ? new OperacionCanceladaError() : e;
}

/** Espera abortable: se corta de inmediato si el usuario cancela. */
function esperar(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new OperacionCanceladaError());
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new OperacionCanceladaError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

// ---------------------------------------------------------------------------
//  Candado de solo lectura
// ---------------------------------------------------------------------------

const ACCIONES_ESCRITURA = new Set([
  "set", "edit", "delete", "rename", "clone", "move", "override", "multi-move",
]);

const TIPOS_PROHIBIDOS = new Set(["commit", "import", "user-id"]);

// Contenedores de Custom Reports: lo unico que se puede escribir por la via
// de configuracion. Cubre shared y los reports por vsys, nada mas.
//
// El tramo final acepta subnodos del reporte (type/trsum, period...), pero
// NO cualquier cosa: la version anterior usaba (\/.*)? y eso dejaba pasar
// '/config/shared/reports/../address', que con un motor XPath que resuelva
// '..' habria alcanzado objetos o reglas. El candado es una garantia de
// diseno, asi que el tramo se limita a segmentos con forma de nodo.
const SEGMENTO_XPATH = "[A-Za-z0-9_.-]+(\\[@?[A-Za-z0-9_.-]+='[^'\\]]*'\\])?";
const XPATH_REPORTES_ESCRIBIBLE = new RegExp(
  "^/config/(shared|devices/entry(\\[@name='[^'\\]]*'\\])?/vsys/entry\\[@name='[^'\\]]*'\\])" +
    "/reports(/" + SEGMENTO_XPATH + ")*$"
);

/**
 * Construcciones de XPath que permitirian salirse del subarbol autorizado.
 * Ojo: corchetes y comillas simples NO van aqui, porque son legitimos en un
 * predicado como entry[@name='X'] — la forma de esos predicados ya la acota
 * SEGMENTO_XPATH.
 *
 *   ..   nodo padre        -> subir fuera de /reports
 *   .    nodo actual       -> segmento inutil, senal de ruta manipulada
 *   |    union             -> anadir una segunda ruta
 *   //   descendant-or-self
 *   ( )  llamadas a funcion
 */
const XPATH_PELIGROSO = /(^|\/)\.{1,2}(\/|$)|\||\/\/|[()]/;

/**
 * Sanea un valor que se va a interpolar dentro de un predicado XPath
 * (nombre de vsys, de device-group, de reporte). Sin esto, un valor con una
 * comilla rompe la consulta y, peor, permite reescribir la ruta.
 */
export function sanearValorXpath(valor) {
  return String(valor || "").replace(/[^A-Za-z0-9_.\- ]/g, "").trim();
}

export class OperacionBloqueadaError extends Error {
  constructor(message) {
    super(message);
    this.name = "OperacionBloqueadaError";
  }
}

/** Lanza si los parametros describen una operacion que modifica el equipo. */
export function verificarSoloLectura(params) {
  const tipo = String(params.type || "").toLowerCase();
  const accion = String(params.action || "").toLowerCase();

  if (TIPOS_PROHIBIDOS.has(tipo)) {
    throw new OperacionBloqueadaError(
      `Operacion bloqueada: type='${tipo}' modifica el equipo. ` +
        `PAN Helper v0.2 es de solo lectura.`
    );
  }

  if (tipo === "config" && accion !== "get" && accion !== "show") {
    // UNICA excepcion al candado: guardar la definicion de un Custom Report.
    // Se limita por xpath a los contenedores de reports (shared o vsys) y
    // solo admite 'set'. No alcanza a politicas, objetos ni nada mas, y
    // sigue sin existir commit: lo escrito queda en la candidate config.
    const xpath = String(params.xpath || "");
    if (
      accion === "set" &&
      !XPATH_PELIGROSO.test(xpath) &&
      XPATH_REPORTES_ESCRIBIBLE.test(xpath)
    ) {
      return;
    }
    throw new OperacionBloqueadaError(
      `Operacion bloqueada: config action='${accion || "(vacia)"}' no es de lectura. ` +
        `La unica escritura permitida por esta via es guardar un Custom Report.`
    );
  }

  // Comandos operacionales que escriben, borran o reinician.
  if (tipo === "op") {
    const cmd = String(params.cmd || "").toLowerCase();
    if (/<commit|<delete|<set |<load|<restore|<revert|<request\s*>?\s*<(restart|shutdown)/.test(cmd)) {
      throw new OperacionBloqueadaError(
        `Operacion bloqueada: el comando operacional modifica el equipo. ` +
          `PAN Helper v0.2 es de solo lectura. Comando: ${cmd.slice(0, 80)}`
      );
    }
  }
}

// ---------------------------------------------------------------------------
//  Nucleo HTTP
// ---------------------------------------------------------------------------

export function baseUrlFor(target) {
  const port = target.port && Number(target.port) !== 443 ? `:${target.port}` : "";
  return `https://${target.host}${port}`;
}

function errorDeRed(baseUrl, err) {
  const host = new URL(baseUrl).host;
  return new Error(
    `No se pudo conectar con ${host}. Causas frecuentes: el certificado ` +
      `autofirmado aun no ha sido aceptado (abre https://${host} en una ` +
      `pestana y acepta la advertencia), el equipo no responde, o no hay ` +
      `ruta por la VPN. Detalle: ${err.message}`
  );
}

async function apiCall(baseUrl, params) {
  verificarSoloLectura(params);

  const tipo = params.type || "?";
  const accion = params.action ? ` action=${params.action}` : "";
  trace(`API POST ${new URL(baseUrl).host}: type=${tipo}${accion}`);

  let res;
  try {
    res = await fetch(`${baseUrl}/api/`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params).toString(),
      signal: senalActual(),
    });
  } catch (e) {
    if (e?.name === "AbortError") throw new OperacionCanceladaError();
    throw errorDeRed(baseUrl, e);
  }
  let text;
  try {
    text = await res.text();
  } catch (e) {
    throw traducirAbort(e);
  }
  return unwrapApiResponse(parseXml(text));
}

// ---------------------------------------------------------------------------
//  Autenticacion e identificacion
// ---------------------------------------------------------------------------

// Cambia usuario/contrasena por una API key. La contrasena se usa aqui una
// unica vez y no se persiste en ningun lado.
export async function keygen(baseUrl, username, password) {
  const result = await apiCall(baseUrl, { type: "keygen", user: username, password });
  const key = result?.querySelector("key")?.textContent?.trim();
  if (!key) {
    throw new Error(
      "El equipo no devolvio API key. Credenciales incorrectas o el usuario " +
        "no tiene habilitado el acceso por API."
    );
  }
  return key;
}

/**
 * Comando operacional. `vsys` acota el comando a un vsys concreto: PAN-OS
 * responde con lo que ve ese vsys, no lo compartido (lo usa la consulta de
 * certificados en equipos multi-vsys).
 */
export async function op(baseUrl, apiKey, cmdXml, { vsys = null } = {}) {
  const params = { type: "op", cmd: cmdXml, key: apiKey };
  if (vsys) params.vsys = vsys;
  return apiCall(baseUrl, params);
}

/**
 * Lee un xpath que apunta a atributos (p. ej. .../entry/@name) y devuelve
 * los nombres. Sirve para listar vsys y templates sin descargarse su
 * configuracion entera.
 */
export async function listarNombres(baseUrl, apiKey, xpath) {
  const result = await apiCall(baseUrl, { type: "config", action: "get", xpath, key: apiKey });
  if (!result) return [];
  return Array.from(result.querySelectorAll("entry"))
    .map((e) => e.getAttribute("name"))
    .filter(Boolean);
}

export async function getSystemInfo(baseUrl, apiKey) {
  const result = await op(baseUrl, apiKey, "<show><system><info></info></system></show>");
  const info = result?.querySelector("system");
  if (!info) throw new Error("Respuesta inesperada de 'show system info'.");
  const leer = (tag) => info.querySelector(tag)?.textContent?.trim() || null;
  return {
    devicename: leer("devicename"),
    hostname: leer("hostname") || "desconocido",
    serial: leer("serial"),
    model: leer("model") || "desconocido",
    swVersion: leer("sw-version") || "desconocido",
    // El campo model de "show system info" en Panorama dice "Panorama".
    isPanorama: /panorama/i.test(leer("model") || ""),
    // 'on' cuando el firewall tiene multiples vsys: los certificados hay que
    // pedirlos entonces por cada vsys, ademas de los compartidos.
    multiVsys: (leer("multi-vsys") || "").toLowerCase() === "on",
  };
}

// ---------------------------------------------------------------------------
//  Configuracion (lectura)
// ---------------------------------------------------------------------------

// Running config completa como un solo <config>: lo activo/efectivo ahora
// (en un firewall administrado incluye la politica empujada por Panorama).
export async function getRunningConfig(baseUrl, apiKey) {
  const result = await op(baseUrl, apiKey, "<show><config><running></running></config></show>");
  const config = result?.querySelector("config");
  if (!config) throw new Error("La running config no contiene un elemento <config>.");
  return config;
}

// type=config&action=get con xpath devuelve el elemento apuntado, envuelto
// en <result>. xpath='/config' trae el arbol candidate completo (lo staged
// sin commitear). El candado solo permite action=get/show.
export async function getConfig(baseUrl, apiKey, xpath) {
  const result = await apiCall(baseUrl, { type: "config", action: "get", xpath, key: apiKey });
  return result?.firstElementChild || null;
}

export async function getCandidateConfig(baseUrl, apiKey) {
  const config = await getConfig(baseUrl, apiKey, "/config");
  if (!config) throw new Error("La candidate config llego vacia.");
  return config;
}

// ---------------------------------------------------------------------------
//  Export de archivos (backups)
// ---------------------------------------------------------------------------

// Se intenta primero POST, con la key en el cuerpo. Hasta v0.2.7 esto iba
// siempre por GET, lo que dejaba la API key en la URL y por tanto en el log
// del servidor web del propio equipo y en cualquier proxy que intercepte
// TLS. Se conserva GET como respaldo porque el endpoint de export no acepta
// POST de forma consistente entre versiones de PAN-OS, y el modulo de
// backups de v0.1 se verifico en produccion por esa via.
//
// El respaldo es seguro: un export es de solo lectura, asi que un POST que
// el equipo rechace no deja efecto alguno.
async function descargarExport(baseUrl, params, etiqueta) {
  verificarSoloLectura(params);

  const host = new URL(baseUrl).host;

  /**
   * Un intento por un verbo concreto.
   * @returns {{blob}|{errorXml}|null}
   *   blob     -> exportacion valida
   *   errorXml -> el equipo respondio, pero con un error de negocio
   *   null     -> el verbo no sirve aqui (HTTP 4xx/5xx)
   */
  const intentar = async (metodo) => {
    let res;
    try {
      res =
        metodo === "POST"
          ? await fetch(`${baseUrl}/api/`, {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams(params).toString(),
              signal: senalActual(),
            })
          : await fetch(`${baseUrl}/api/?${new URLSearchParams(params)}`, {
              method: "GET",
              signal: senalActual(),
            });
    } catch (e) {
      if (e?.name === "AbortError") throw new OperacionCanceladaError();
      // Un fallo de red no se reintenta con el otro verbo: el equipo no esta
      // accesible y cambiar de metodo no lo va a arreglar.
      throw errorDeRed(baseUrl, e);
    }

    if (!res.ok) return null;

    let blob;
    try {
      blob = await res.blob();
    } catch (e) {
      throw traducirAbort(e);
    }

    if (blob.size === 0) return null;

    // Un export fallido devuelve una respuesta XML de error, siempre pequena.
    // Solo se inspecciona ese caso; una config valida se devuelve tal cual.
    if (blob.size < 4096) {
      const texto = await blob.text();
      if (texto.includes("<response") && texto.includes('status="error"')) {
        return { errorXml: texto };
      }
      // Contenido legitimo pero pequeno: el blob ya fue consumido, se rehace.
      return { blob: new Blob([texto], { type: blob.type || "application/octet-stream" }) };
    }

    return { blob };
  };

  trace(`API POST ${host}: type=export ${etiqueta}`);
  let intento = await intentar("POST");

  // Se cae a GET tanto si el POST fue rechazado a nivel HTTP como si el
  // equipo respondio 200 con un XML de error: ambas cosas significan que
  // esta version de PAN-OS no atiende el export por POST.
  if (!intento || intento.errorXml) {
    trace(`${host}: el export no funciono por POST; reintentando por GET.`);
    const porGet = await intentar("GET");
    if (porGet) intento = porGet;
  }

  if (!intento) {
    throw new Error(
      `El equipo rechazo la exportacion de '${etiqueta}' tanto por POST como por GET.`
    );
  }

  // Si tambien GET trajo error de negocio, se propaga el detalle del equipo.
  if (intento.errorXml) {
    unwrapApiResponse(parseXml(intento.errorXml));
  }

  return intento.blob;
}

/** Export directo: la respuesta ES el archivo (configuration, device-state). */
export async function exportFile(baseUrl, apiKey, category) {
  return descargarExport(baseUrl, { type: "export", category, key: apiKey }, `category=${category}`);
}

/**
 * Export asincrono: el equipo no devuelve el archivo, devuelve un job que hay
 * que esperar antes de recogerlo. Es como funciona 'stats-dump'.
 *
 * El script original hacia poll cada 100 ms sin limite: si un job se colgaba,
 * martilleaba el firewall indefinidamente. Aqui hay intervalo razonable y
 * tope de intentos.
 *
 * Tambien comprueba el RESULTADO del job. El original solo salia del bucle
 * cuando el estado dejaba de ser PEND y descargaba a continuacion, asi que un
 * job terminado en FAIL producia un .tar.gz con un XML de error dentro, sin
 * que nadie se enterara.
 *
 * @param {object} opciones {intervaloMs, maxIntentos, onProgreso}
 *        onProgreso(porcentaje, estado) para reportar el avance.
 */
export async function exportarConJob(baseUrl, apiKey, category, opciones = {}) {
  const { intervaloMs = 2000, maxIntentos = 90, onProgreso = null } = opciones;

  // --- 1. Solicitud: devuelve el job-id ---
  const envio = await apiCall(baseUrl, { type: "export", category, key: apiKey });
  const jobId = envio?.querySelector("job")?.textContent?.trim();
  if (!jobId) {
    throw new Error(
      `El equipo no devolvio job-id al pedir '${category}'. ` +
        `Puede que esta plataforma no soporte esa categoria de export.`
    );
  }
  trace(`Export '${category}': job ${jobId} enviado.`);

  // --- 2. Espera ---
  for (let intento = 1; intento <= maxIntentos; intento++) {
    const res = await op(baseUrl, apiKey, `<show><jobs><id>${jobId}</id></jobs></show>`);
    const job = res?.querySelector("job");

    const estado = job?.querySelector("status")?.textContent?.trim() || "";
    const resultado = job?.querySelector("result")?.textContent?.trim() || "";
    const progreso = job?.querySelector("progress")?.textContent?.trim() || "";

    if (onProgreso) onProgreso(progreso, resultado || estado);

    // Terminado: PAN-OS marca status=FIN y result=OK|FAIL.
    if (estado === "FIN" || (resultado && resultado !== "PEND")) {
      if (resultado === "FAIL") {
        const detalle =
          job?.querySelector("details")?.textContent?.trim() ||
          job?.querySelector("warnings")?.textContent?.trim() ||
          "sin detalle";
        throw new Error(`El job ${jobId} de '${category}' termino en FAIL: ${detalle}`);
      }
      trace(`Export '${category}': job ${jobId} listo (${resultado || estado}).`);

      // --- 3. Recogida del archivo ---
      return descargarExport(
        baseUrl,
        { type: "export", category, action: "get", "job-id": jobId, key: apiKey },
        `category=${category} job=${jobId}`
      );
    }

    await esperar(intervaloMs, senalActual());
  }

  throw new Error(
    `El job ${jobId} de '${category}' no termino tras ${maxIntentos} intentos ` +
      `(${Math.round((maxIntentos * intervaloMs) / 1000)} s).`
  );
}

// ---------------------------------------------------------------------------
//  Custom reports (fuente alternativa para el hardening App-ID)
//
//  En vez de recorrer los logs crudos, se puede reutilizar un Custom Report
//  ya creado en el equipo. Los reportes utiles para esto son de tipo
//  Traffic Summary (trsum) agregados por regla y aplicacion, p. ej.:
//
//    set shared reports <nombre> type trsum sortby sessions
//    set shared reports <nombre> type trsum aggregate-by [ rule app dport dst src ]
//    set shared reports <nombre> period last-90-calendar-days
//    set shared reports <nombre> topn 100
//    set shared reports <nombre> topm 25
//    set shared reports <nombre> caption <nombre>
//
//  La extension NO crea el reporte (eso es escritura de configuracion, que
//  el candado prohibe): lo lee, reutiliza su definicion y lo corre ad hoc.
//  Para crearlo, el dashboard genera los comandos SET para copiar y pegar.
//
//  Todas las llamadas de esta seccion son de lectura: type=config&action=get
//  para la definicion y type=report para ejecutarlo.
// ---------------------------------------------------------------------------

/** Contenedor por defecto de los Custom Reports (los del ejemplo son shared). */
export const XPATH_REPORTES_SHARED = "/config/shared/reports";

const escXml = (s) =>
  String(s).replace(/[<>&'"]/g, (c) =>
    ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c])
  );

/**
 * <type> de un reporte Traffic Summary agregado por regla y aplicacion:
 * el equivalente XML de
 *   set ... type trsum sortby sessions
 *   set ... type trsum aggregate-by [ rule app dport dst src ]
 */
export function construirTypeTrsum(agregarPor = ["rule", "app", "dport", "dst", "src"]) {
  const miembros = agregarPor.map((m) => `<member>${escXml(m)}</member>`).join("");
  return (
    "<type><trsum>" +
    "<sortby>sessions</sortby>" +
    `<aggregate-by>${miembros}</aggregate-by>` +
    "</trsum></type>"
  );
}

/**
 * Query que acota el reporte a un conjunto de politicas:
 *   (rule eq 'pol-1') or (rule eq 'pol-2')
 * Devuelve null si no hay politicas (reporte sin filtro de regla).
 */
export function construirQueryReglas(reglas) {
  const lista = (reglas || []).map((r) => String(r).replace(/'/g, "").trim()).filter(Boolean);
  if (!lista.length) return null;
  return lista.map((r) => `(rule eq '${r}')`).join(" or ");
}

/**
 * Guarda (o sobreescribe) la definicion de un Custom Report en la CANDIDATE
 * config, con la misma forma que producen los comandos SET del CLI.
 *
 * ESTA ES LA UNICA ESCRITURA DE CONFIGURACION DE TODO panApi.js, y el
 * candado la limita por xpath a los contenedores de reports. NO hace commit:
 * la definicion queda en candidate y hay que commitearla en la GUI para que
 * aparezca de forma permanente en Monitor > Manage Custom Reports.
 *
 * Ejecutar el reporte NO requiere esto: ejecutarReporteAdHoc() corre la
 * definicion al vuelo. Guardarla sirve para dejar rastro y poder reutilizarla
 * desde la GUI.
 */
export async function guardarDefinicionReporte(baseUrl, apiKey, opciones = {}) {
  const {
    nombre,
    containerXpath = XPATH_REPORTES_SHARED,
    periodo = "last-90-calendar-days",
    topn = 500,
    topm = 25,
    query = null,
    agregarPor,
  } = opciones;

  if (!nombre) throw new Error("Falta el nombre del reporte a guardar.");

  const element =
    `<entry name="${escXml(nombre)}">` +
    construirTypeTrsum(agregarPor) +
    `<period>${escXml(periodo)}</period>` +
    `<topn>${Number(topn) || 500}</topn>` +
    `<topm>${Number(topm) || 25}</topm>` +
    `<caption>${escXml(nombre)}</caption>` +
    (query ? `<query>${escXml(query)}</query>` : "") +
    `</entry>`;

  trace(`Guardando definicion del reporte '${nombre}' en ${containerXpath}.`);

  return apiCall(baseUrl, {
    type: "config",
    action: "set",
    xpath: containerXpath,
    element,
    key: apiKey,
  });
}

/** Nombres de los Custom Reports guardados en un contenedor. */
export async function listarReportes(baseUrl, apiKey, containerXpath = XPATH_REPORTES_SHARED) {
  const contenedor = await getConfig(baseUrl, apiKey, containerXpath);
  if (!contenedor) return [];
  return Array.from(contenedor.children)
    .filter((e) => e.tagName === "entry")
    .map((e) => e.getAttribute("name"))
    .filter(Boolean);
}

/** Definicion completa de un Custom Report (elemento <entry>). */
export async function obtenerDefinicionReporte(
  baseUrl, apiKey, nombre, containerXpath = XPATH_REPORTES_SHARED
) {
  const xpath = `${containerXpath}/entry[@name='${sanearValorXpath(nombre)}']`;
  const entry = await getConfig(baseUrl, apiKey, xpath);
  if (!entry) {
    throw new Error(
      `No se encontro el Custom Report '${nombre}' en ${containerXpath}. ` +
        `Verifica el nombre y el contenedor (shared vs vsys).`
    );
  }
  return entry;
}

/**
 * Resume una definicion para mostrarla antes de ejecutarla: base de datos,
 * columnas de agregacion, periodo, topn/topm y query embebida.
 */
export function describirReporte(entry) {
  const hijo = (el, tag) => Array.from(el?.children || []).find((c) => c.tagName === tag) || null;
  const texto = (el) => (el ? el.textContent.trim() : "");

  const tipoEl = hijo(entry, "type");
  // El primer hijo de <type> es la base de datos: trsum, thsum, appstat...
  const baseEl = tipoEl ? tipoEl.firstElementChild : null;

  return {
    nombre: entry.getAttribute("name"),
    base: baseEl ? baseEl.tagName : null,
    agregadoPor: baseEl
      ? Array.from(hijo(baseEl, "aggregate-by")?.children || []).map((m) => m.textContent.trim())
      : [],
    ordenadoPor: texto(hijo(baseEl, "sortby")),
    periodo: texto(hijo(entry, "period")),
    topn: texto(hijo(entry, "topn")),
    topm: texto(hijo(entry, "topm")),
    query: texto(hijo(entry, "query")),
    typeXml: tipoEl ? tipoEl.outerHTML : null,
  };
}

/**
 * Ejecuta un reporte ad hoc reutilizando el <type> de una definicion
 * guardada. Los parametros opcionales sobreescriben los de la definicion
 * solo para esta corrida; el reporte guardado no se modifica.
 *
 * @returns {string} job-id
 */
export async function ejecutarReporteAdHoc(baseUrl, apiKey, typeXml, opciones = {}) {
  if (!typeXml) throw new Error("La definicion del reporte no tiene elemento <type>.");

  const { periodo, topn, topm, query } = opciones;
  const esc = (s) =>
    String(s).replace(/[<>&'"]/g, (c) =>
      ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c])
    );

  let cmd = typeXml;
  if (periodo) cmd += `<period>${esc(periodo)}</period>`;
  if (topn) cmd += `<topn>${Number(topn) || 100}</topn>`;
  if (topm) cmd += `<topm>${Number(topm) || 25}</topm>`;
  if (query) cmd += `<query>${esc(query)}</query>`;

  const result = await apiCall(baseUrl, {
    type: "report",
    reporttype: "dynamic",
    reportname: "pan-helper-adhoc",
    cmd,
    key: apiKey,
  });

  const jobId = result?.querySelector("job")?.textContent?.trim();
  if (!jobId) throw new Error("La ejecucion del reporte no devolvio job-id.");
  trace(`Reporte enviado; job ${jobId}.`);
  return jobId;
}

/**
 * Poll de un job de reporte hasta que termina. Devuelve las filas como
 * objetos planos, con las columnas que haya definido el reporte.
 */
export async function esperarReporte(baseUrl, apiKey, jobId, opciones = {}) {
  const { intervaloMs = 2000, maxIntentos = 60, onEspera = null } = opciones;

  for (let intento = 1; intento <= maxIntentos; intento++) {
    const result = await apiCall(baseUrl, {
      type: "report",
      action: "get",
      "job-id": jobId,
      key: apiKey,
    });

    const status = result?.querySelector("job > status")?.textContent?.trim();

    // Cuando termina, segun la version de PAN-OS las filas cuelgan de
    // <report> o directamente de <result>. Se aceptan ambas formas.
    if (!status || status === "FIN") {
      const entradas =
        result.querySelectorAll("report > entry").length
          ? result.querySelectorAll("report > entry")
          : result.querySelectorAll(":scope > entry");

      if (!status && !entradas.length) continue; // aun sin datos; reintentar

      const filas = Array.from(entradas).map((e) => {
        const fila = {};
        for (const col of e.children) fila[col.tagName] = col.textContent.trim();
        return fila;
      });
      trace(`Job ${jobId} terminado: ${filas.length} fila(s) de reporte.`);
      return filas;
    }

    if (onEspera) onEspera(intento, maxIntentos);
    await esperar(intervaloMs, senalActual());
  }

  throw new Error(
    `El reporte (job ${jobId}) no termino tras ${maxIntentos} intentos. ` +
      `Reduce el periodo o el topn del reporte.`
  );
}

// ---------------------------------------------------------------------------
//  Consulta de logs (hardening App-ID)
// ---------------------------------------------------------------------------

// PAN-OS resuelve las consultas de log de forma asincrona: se envia la
// query, devuelve un job-id, y hay que hacer poll hasta status=FIN.
//
// @param {string} query    filtro en sintaxis de PAN-OS
// @param {object} opciones {logType, nlogs, vsys, intervaloMs, maxIntentos, onEspera}
//        `vsys` acota la consulta a un vsys concreto. En equipos multi-vsys
//        es necesario: sin el, se mezclan sesiones de otros vsys que tengan
//        una regla con el mismo nombre.
// @returns {Array<Object>} entradas del log como objetos planos
export async function queryLogs(baseUrl, apiKey, query, opciones = {}) {
  const {
    logType = "traffic",
    nlogs = 5000,
    vsys = null,
    intervaloMs = 2000,
    maxIntentos = 60,
    onEspera = null,
  } = opciones;

  // --- envio de la consulta ---
  const paramsEnvio = {
    type: "log",
    "log-type": logType,
    query,
    nlogs: String(nlogs),
    key: apiKey,
  };
  if (vsys) paramsEnvio.vsys = vsys;

  const envio = await apiCall(baseUrl, paramsEnvio);
  const jobId = envio?.querySelector("job")?.textContent?.trim();
  if (!jobId) {
    throw new Error("La consulta de logs no devolvio job-id.");
  }
  trace(`Job de logs ${jobId} enviado; esperando FIN...`);

  // --- poll hasta FIN ---
  for (let intento = 1; intento <= maxIntentos; intento++) {
    const result = await apiCall(baseUrl, {
      type: "log",
      action: "get",
      "job-id": jobId,
      key: apiKey,
    });

    const status = result?.querySelector("job > status")?.textContent?.trim();

    if (status === "FIN") {
      const entradas = Array.from(result.querySelectorAll("log > logs > entry")).map((entry) => {
        const fila = {};
        for (const hijo of entry.children) {
          fila[hijo.tagName] = hijo.textContent;
        }
        return fila;
      });
      trace(`Job ${jobId} terminado: ${entradas.length} entradas.`);
      return entradas;
    }

    if (onEspera) onEspera(intento, maxIntentos);
    await esperar(intervaloMs, senalActual());
  }

  throw new Error(
    `El job de logs ${jobId} no termino tras ${maxIntentos} intentos. ` +
      `Reduce la ventana de dias o el numero de logs.`
  );
}

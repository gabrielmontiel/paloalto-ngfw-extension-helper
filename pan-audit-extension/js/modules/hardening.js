// js/modules/hardening.js
// Modulo: hardening de reglas con App-ID.
//
// v0.2.2 — port del descubrimiento iterativo de analizadorAppId-REST.py:
// en vez de tomar UNA muestra grande de logs (que deja aplicaciones por
// fuera si la muestra se llena de las apps mas ruidosas), se consultan los
// logs por TANDAS de 1000, negando en la query las aplicaciones ya
// conocidas ((app neq 'x') and (app neq 'y')...) hasta que una tanda llega
// vacia o sin apps nuevas. Asi el descubrimiento es exhaustivo: cada
// iteracion solo puede traer aplicaciones que aun no se han visto.
//
// Igual que el script original:
//  - Solo trafico permitido: (action eq 'allow') dentro de la query.
//  - Ruido ({incomplete}) pre-cargado como "ya conocido": se niega desde la
//    primera tanda y nunca se recomienda.
//  - Apps de baja visibilidad (insufficient-data, unknown-*) se descubren y
//    reportan APARTE como alerta; nunca se recomiendan.
//  - Limite de 100 iteraciones por regla como salvaguarda.
//  - Las reglas se procesan en secuencia, una a la vez.
//
// v0.2.3 — se porta tambien la Fase 2 del script como clonarYAjustar():
// para las politicas que el usuario MARQUE, clona la regla original via
// REST, reemplaza application por las apps descubiertas, crea
// "<Politica>-AppID" en la CANDIDATE config y la mueve antes de la
// original. SIN COMMIT: no existe esa capacidad en la extension (ver
// panRestApi.js); revisar y hacer commit en la GUI es obligatorio. El
// analisis en si sigue siendo de solo lectura (candado de panApi.js).
//
// ALCANCE EXPLICITO: se analizan EXACTAMENTE las politicas que indica el
// usuario, en el orden en que las indica; se clonan EXACTAMENTE las que
// marca, previa confirmacion.

import {
  baseUrlFor,
  getSystemInfo,
  queryLogs,
  listarReportes,
  obtenerDefinicionReporte,
  describirReporte,
  ejecutarReporteAdHoc,
  esperarReporte,
  construirTypeTrsum,
  construirQueryReglas,
  guardarDefinicionReporte,
  XPATH_REPORTES_SHARED,
} from "../lib/panApi.js";
import {
  obtenerReglaSecurity,
  crearReglaSecurity,
  actualizarReglaSecurity,
  moverReglaAntesDe,
  restVersionFromSw,
} from "../lib/panRestApi.js";
import { nombreSeguro, aCsv, descargarTexto } from "../lib/util.js";

// --- Parametros del descubrimiento (equivalen a los del script) ---
const NLOGS_POR_TANDA = 1000;
const MAX_ITERACIONES = 100;

// Ruido: nunca debe terminar en la lista recomendada. Se pre-carga como
// "ya conocido" desde el arranque (se niega desde la primera query).
const APLICACIONES_RUIDO = new Set(["incomplete"]);

// Baja visibilidad: se detectan y reportan aparte, NUNCA se recomiendan.
// Requieren revision manual (SSL decryption, App-ID cloud...).
const APLICACIONES_ALERTA = new Set([
  "insufficient-data", "unknown-tcp", "unknown-udp", "unknown-p2p",
]);

const CARPETA_RAIZ = "PAN-Helper";

// ---------------------------------------------------------------------------
//  Query de descubrimiento
// ---------------------------------------------------------------------------

function fechaPanOs(date) {
  const p = (n) => String(n).padStart(2, "0");
  return (
    `${date.getFullYear()}/${p(date.getMonth() + 1)}/${p(date.getDate())} ` +
    `${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`
  );
}

const sinComillas = (s) => String(s).replace(/'/g, "");

/**
 * Sub-filtro de device_name para Panorama. Con un solo dispositivo no
 * envuelve en parentesis extra; con varios arma un OR envuelto en un
 * parentesis exterior para que el AND del resto lo trate como un bloque.
 * Exportada para poder probarla sin red.
 */
export function construirFiltroDispositivos(dispositivos) {
  const lista = (dispositivos || []).map(sinComillas).filter(Boolean);
  if (!lista.length) return null;
  if (lista.length === 1) return `(device_name eq '${lista[0]}')`;
  return "(" + lista.map((d) => `(device_name eq '${d}')`).join(" or ") + ")";
}

/**
 * Filtro: regla + dispositivo(s) + ventana de tiempo + solo permitido +
 * negacion de todas las apps ya conocidas. Exportada para poder probarla
 * sin red.
 *
 * `dispositivos` solo aplica en Panorama: acota los logs a firewalls
 * concretos. En un firewall va vacio.
 */
export function construirQueryDescubrimiento(nombreRegla, appsConocidas, desde, dispositivos = null) {
  // Las comillas simples delimitan el valor en la sintaxis de PAN-OS.
  const partes = [`(rule eq '${sinComillas(nombreRegla)}')`];

  const filtroDispositivos = construirFiltroDispositivos(dispositivos);
  if (filtroDispositivos) partes.push(filtroDispositivos);

  partes.push(`(receive_time geq '${fechaPanOs(desde)}')`);
  partes.push(`(action eq 'allow')`); // CRITICO: solo trafico realmente permitido

  for (const app of [...appsConocidas].sort()) {
    partes.push(`(app neq '${sinComillas(app)}')`);
  }
  return partes.join(" and ");
}

// ---------------------------------------------------------------------------
//  Descubrimiento de aplicaciones para UNA politica
// ---------------------------------------------------------------------------

/**
 * Devuelve { recomendadas, alerta, iteraciones } para una politica.
 *  - recomendadas: apps reales (sin ruido, sin alerta), Set.
 *  - alerta: apps de baja visibilidad detectadas, Set.
 */
async function descubrirAplicaciones(baseUrl, apiKey, nombreRegla, desde, vsys, dispositivos, log) {
  const conocidas = new Set(APLICACIONES_RUIDO); // el ruido nunca cuenta como descubrimiento
  const alertaEncontradas = new Set();
  let iteracion = 0;

  while (true) {
    if (iteracion >= MAX_ITERACIONES) {
      log(
        `${nombreRegla}: limite de ${MAX_ITERACIONES} iteraciones alcanzado sin vaciar. ` +
          `Revisar el filtro o la cantidad de apps distintas.`,
        "warn"
      );
      break;
    }
    iteracion++;

    const query = construirQueryDescubrimiento(nombreRegla, conocidas, desde, dispositivos);
    log(
      `${nombreRegla}: iteracion ${iteracion} | apps conocidas: ${conocidas.size} | ` +
        `tanda de hasta ${NLOGS_POR_TANDA} logs...`,
      "debug"
    );

    const entradas = await queryLogs(baseUrl, apiKey, query, {
      logType: "traffic",
      nlogs: NLOGS_POR_TANDA,
      vsys,
      onEspera: (intento) => {
        if (intento % 5 === 0) {
          log(`  ${nombreRegla}: esperando al firewall (${intento})...`);
        }
      },
    });

    if (!entradas.length) {
      log(`${nombreRegla}: tanda vacia. Descubrimiento completo.`, "debug");
      break;
    }

    const appsEnTanda = new Set(
      entradas.map((e) => String(e.app || "").trim()).filter(Boolean)
    );
    const nuevas = [...appsEnTanda].filter((a) => !conocidas.has(a));

    if (!nuevas.length) {
      log(`${nombreRegla}: tanda con logs pero sin apps nuevas. Deteniendo.`, "warn");
      break;
    }

    const nuevasAlerta = nuevas.filter((a) => APLICACIONES_ALERTA.has(a));
    const nuevasNormales = nuevas.filter((a) => !APLICACIONES_ALERTA.has(a));

    if (nuevasAlerta.length) {
      for (const a of nuevasAlerta) alertaEncontradas.add(a);
      log(
        `${nombreRegla}: apps de baja visibilidad detectadas (revision manual, ` +
          `NO se recomiendan): ${nuevasAlerta.sort().join(", ")}`,
        "warn"
      );
    }

    if (nuevasNormales.length) {
      log(
        `${nombreRegla}: ${entradas.length} logs en la tanda | nuevas: ${nuevasNormales.sort().join(", ")}`
      );
    }

    for (const a of nuevas) conocidas.add(a);
  }

  const recomendadas = new Set(
    [...conocidas].filter((a) => !APLICACIONES_RUIDO.has(a) && !alertaEncontradas.has(a))
  );

  return { recomendadas, alerta: alertaEncontradas, iteraciones: iteracion };
}

// ---------------------------------------------------------------------------
//  Punto de entrada
// ---------------------------------------------------------------------------

/**
 * @param {{target, reglas: string[], dias, descargarCsv: boolean,
 *          vsys?: string|null, deviceGroup?: string|null,
 *          dispositivos?: string[]|null}} config
 *        `target` es una conexion guardada; `reglas` es la lista explicita
 *        del usuario; `descargarCsv` controla si al final se descarga el
 *        CSV resumen. En Panorama, `deviceGroup` queda registrado en el
 *        resumen y `dispositivos` acota los logs a firewalls concretos.
 * @param {(mensaje: string, nivel?: string) => void} log
 * @param {(hechos: number, total: number) => void} onProgreso
 */
export async function ejecutarHardening(config, log, onProgreso) {
  const { target, reglas, dias, vsys, deviceGroup, dispositivos, descargarCsv } = config;

  if (!reglas?.length) {
    throw new Error("No se indico ninguna politica a analizar.");
  }

  const baseUrl = baseUrlFor(target);
  const esPanorama = /panorama/i.test(target.platform || "");

  const info = await getSystemInfo(baseUrl, target.apiKey);
  const nombreEquipo = nombreSeguro(info.devicename || info.hostname || target.host);
  log(`Conectado a ${nombreEquipo} (${info.model}, PAN-OS ${info.swVersion}).`, "ok");
  log("Modo solo lectura: no se modificara la configuracion.", "ok");

  const desde = new Date(Date.now() - dias * 24 * 60 * 60 * 1000);
  log(`${reglas.length} politica(s), en secuencia (una a la vez, como el script original).`);
  log(
    `Descubrimiento iterativo: tandas de ${NLOGS_POR_TANDA} logs negando las apps ya ` +
      `conocidas, hasta ${MAX_ITERACIONES} iteraciones por regla.`
  );
  log(`Ventana de trafico desde ${fechaPanOs(desde)} (${dias} dias).`);

  if (esPanorama) {
    log(`Panorama: device-group '${deviceGroup || "(no indicado)"}'.`);
    if (dispositivos?.length) {
      log(`Logs acotados a ${dispositivos.length} dispositivo(s): ${dispositivos.join(", ")}.`);
    } else {
      log(
        "Sin dispositivos indicados: los logs vienen de todos los firewalls que reportan " +
          "a este Panorama. Si dos device-groups tienen una regla con el mismo nombre, se " +
          "mezclaran sus sesiones.",
        "warn"
      );
    }
  } else {
    log(vsys ? `Consultas acotadas a ${vsys}.` : "Sin acotar a vsys (todos).");
  }

  // Secuencial a proposito: cada regla puede requerir muchas consultas de
  // log y el script original tambien iba de a una.
  const resumen = [];
  const alertas = [];
  let hechos = 0;

  for (const regla of reglas) {
    log(`--- ${regla} (${hechos + 1}/${reglas.length}) ---`);
    try {
      const { recomendadas, alerta, iteraciones } = await descubrirAplicaciones(
        baseUrl, target.apiKey, regla, desde, esPanorama ? null : vsys, dispositivos, log
      );

      resumen.push({
        Politica: regla,
        "Total Apps": recomendadas.size,
        "Aplicaciones Recomendadas": [...recomendadas].sort().join(" ") || "N/A",
        "Apps Alerta": [...alerta].sort().join(" "),
        Iteraciones: iteraciones,
        Timestamp: fechaPanOs(new Date()),
        // Lista cruda para "Clonar y ajustar"; no va al CSV ni a la tabla.
        _apps: [...recomendadas].sort(),
      });

      if (!recomendadas.size) {
        alertas.push(
          `[ADVERTENCIA] '${regla}': sin trafico permitido util en el periodo — ` +
            `no hay aplicaciones para recomendar.`
        );
      }
      for (const a of [...alerta].sort()) {
        alertas.push(
          `[ADVERTENCIA] '${regla}': trafico '${a}' detectado. Revision manual ` +
            `(SSL decryption, App-ID cloud) antes de cerrar la politica.`
        );
      }

      log(
        `${regla}: ${recomendadas.size} app(s) recomendadas en ${iteraciones} iteracion(es)` +
          (alerta.size ? `, ${alerta.size} app(s) de alerta.` : "."),
        recomendadas.size ? "ok" : "warn"
      );
    } catch (e) {
      log(`${regla}: ${e.message}`, "error");
      resumen.push({
        Politica: regla,
        "Total Apps": 0,
        "Aplicaciones Recomendadas": "ERROR",
        "Apps Alerta": "",
        Iteraciones: -1,
        Timestamp: fechaPanOs(new Date()),
        _apps: [],
      });
      alertas.push(`[ERROR] '${regla}': ${e.message}`);
      // Si el usuario cancelo, no tiene sentido seguir con las demas reglas.
      if (e.name === "OperacionCanceladaError") break;
    } finally {
      onProgreso(++hechos, reglas.length);
    }
  }

  // --- exportacion opcional (checkbox en la UI) ---
  if (descargarCsv) {
    const marca = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    const ruta = `${CARPETA_RAIZ}/hardening/${nombreEquipo}_${marca}_resumen.csv`;
    const filasCsv = resumen.map(({ _apps, ...resto }) => resto);
    await descargarTexto(aCsv(filasCsv), ruta);
    log(`CSV resumen en Descargas/${ruta}`, "ok");
  } else {
    log("CSV resumen omitido (checkbox desmarcado). Los resultados quedan en pantalla.");
  }

  for (const a of alertas) log(a, "warn");

  log(`Finalizado. ${resumen.length} regla(s) analizada(s), ${alertas.length} alerta(s).`, "ok");

  return { resumen, alertas };
}

// ===========================================================================
//  FUENTE ALTERNATIVA: Custom Reports
//
//  En vez de recorrer los logs crudos, se reutiliza un Custom Report de tipo
//  Traffic Summary (trsum) agregado por regla y aplicacion. Ventajas: PAN-OS
//  ya tiene los datos pre-agregados (mucho mas rapido que iterar logs) y el
//  periodo puede ser mucho mas largo (last-90-calendar-days sin problema).
//
//  A cambio, la muestra la define el reporte: `topn` limita las filas, asi
//  que una aplicacion muy minoritaria puede quedar fuera. Por eso ambas
//  fuentes conviven: el reporte para barridos amplios y rapidos, la
//  iteracion de logs para exhaustividad sobre pocas reglas.
// ===========================================================================

// Columnas que puede traer el reporte segun como se definio el aggregate-by.
// Se comparan en minusculas para no depender de la version de PAN-OS.
const COLUMNA_REGLA = ["rule", "rulename", "rule-name", "name"];
const COLUMNA_APP = ["app", "application"];
const COLUMNA_SESIONES = ["sessions", "nsess", "count"];

function valorDeColumna(fila, alias) {
  for (const clave of Object.keys(fila)) {
    if (alias.includes(clave.toLowerCase())) return fila[clave];
  }
  return null;
}

/** True si las filas permiten atribuir trafico por regla. */
export function tieneColumnaRegla(filas) {
  return filas.some((f) => valorDeColumna(f, COLUMNA_REGLA) !== null);
}

/**
 * Agrupa las filas del reporte por regla y devuelve, para cada una, las
 * aplicaciones observadas (separando ruido y alerta igual que la via de
 * logs) y el total de sesiones.
 *
 * Exportada para poder probarla sin red.
 *
 * @param {Array<Object>} filas
 * @param {string[]|null} reglasFiltro  si se indica, solo esas politicas
 * @returns {Map<string, {apps:Set, alerta:Set, sesiones:number}>}
 */
export function agruparReportePorRegla(filas, reglasFiltro = null) {
  const permitidas = reglasFiltro?.length ? new Set(reglasFiltro) : null;
  const porRegla = new Map();

  for (const fila of filas) {
    const regla = valorDeColumna(fila, COLUMNA_REGLA);
    const app = valorDeColumna(fila, COLUMNA_APP);
    if (!regla || !app) continue;
    if (permitidas && !permitidas.has(regla)) continue;

    if (!porRegla.has(regla)) {
      porRegla.set(regla, { apps: new Set(), alerta: new Set(), sesiones: 0 });
    }
    const acc = porRegla.get(regla);

    const nombreApp = String(app).trim();
    if (nombreApp && !APLICACIONES_RUIDO.has(nombreApp)) {
      if (APLICACIONES_ALERTA.has(nombreApp)) acc.alerta.add(nombreApp);
      else acc.apps.add(nombreApp);
    }

    const sesiones = Number(valorDeColumna(fila, COLUMNA_SESIONES));
    if (Number.isFinite(sesiones)) acc.sesiones += sesiones;
  }

  return porRegla;
}

/**
 * Comandos SET para crear en el equipo un Custom Report con la forma que
 * este modulo espera. La extension no los ejecuta (crear un reporte es
 * escritura de configuracion, que el candado prohibe): se muestran para
 * copiarlos a una sesion CLI en modo configure.
 */
export function comandosSetReporte(opciones = {}) {
  const {
    nombre = "PAN-Helper-AppID",
    periodo = "last-90-calendar-days",
    topn = 100,
    topm = 25,
    query = "",
    contenedor = "shared",
  } = opciones;

  const base = `set ${contenedor} reports ${nombre}`;
  const lineas = [
    `${base} type trsum sortby sessions`,
    `${base} type trsum aggregate-by [ rule app dport dst src ]`,
    `${base} period ${periodo}`,
    `${base} topn ${topn}`,
    `${base} topm ${topm}`,
    `${base} caption ${nombre}`,
  ];
  if (query) lineas.push(`${base} query "${String(query).replace(/"/g, "'")}"`);
  return lineas.join("\n");
}

/** Nombres de los Custom Reports disponibles en el equipo. */
export async function listarReportesDisponibles(target, containerXpath) {
  return listarReportes(baseUrlFor(target), target.apiKey, containerXpath || XPATH_REPORTES_SHARED);
}

/**
 * Descubre las aplicaciones por politica a partir de un Custom Report.
 *
 * @param {{target, reporte: string, containerXpath?: string,
 *          reglas?: string[]|null, periodo?: string|null,
 *          topn?: number|null, descargarCsv?: boolean}} config
 *        `reglas` es opcional: si se indica, filtra el resultado a esas
 *        politicas; si se omite, se reportan todas las que traiga el
 *        reporte (util cuando la query ya las acota).
 * @returns {{resumen: Array, alertas: Array, descripcion: object}}
 */
export async function ejecutarHardeningDesdeReporte(config, log, onProgreso) {
  const { target, reporte, containerXpath, reglas, periodo, topn, descargarCsv } = config;

  if (!reporte) throw new Error("Indica el nombre del Custom Report a leer.");

  const baseUrl = baseUrlFor(target);
  const contenedor = containerXpath || XPATH_REPORTES_SHARED;

  const info = await getSystemInfo(baseUrl, target.apiKey);
  const nombreEquipo = nombreSeguro(info.devicename || info.hostname || target.host);
  log(`Conectado a ${nombreEquipo} (${info.model}, PAN-OS ${info.swVersion}).`, "ok");
  log("Modo solo lectura: el reporte se ejecuta ad hoc, no se modifica su definicion.", "ok");

  // --- 1. Definicion del reporte ---
  log(`Leyendo la definicion de '${reporte}' en ${contenedor}...`);
  const entry = await obtenerDefinicionReporte(baseUrl, target.apiKey, reporte, contenedor);
  const desc = describirReporte(entry);

  log(
    `Reporte '${desc.nombre}': base=${desc.base || "?"}, ` +
      `agregado por [${desc.agregadoPor.join(", ") || "?"}], ` +
      `periodo=${desc.periodo || "?"}, topn=${desc.topn || "?"}, topm=${desc.topm || "?"}.`
  );
  if (desc.query) log(`Query del reporte: ${desc.query}`, "debug");

  if (desc.base && desc.base !== "trsum") {
    log(
      `El reporte usa la base '${desc.base}'. Este modulo espera 'trsum' ` +
        `(Traffic Summary); si no trae columnas rule y app, no se podra atribuir el trafico.`,
      "warn"
    );
  }
  for (const requerida of ["rule", "app"]) {
    if (desc.agregadoPor.length && !desc.agregadoPor.includes(requerida)) {
      log(
        `El reporte no agrega por '${requerida}'. Agregalo con: ` +
          `set shared reports ${desc.nombre} type trsum aggregate-by [ rule app dport dst src ]`,
        "warn"
      );
    }
  }

  onProgreso(1, 3);

  // --- 2. Ejecucion ad hoc ---
  const periodoEfectivo = periodo || desc.periodo || null;
  log(
    `Ejecutando el reporte ad hoc` +
      (periodoEfectivo ? ` (periodo ${periodoEfectivo})` : "") +
      `. La definicion guardada no se modifica.`
  );

  const jobId = await ejecutarReporteAdHoc(baseUrl, target.apiKey, desc.typeXml, {
    periodo: periodoEfectivo,
    topn: topn || desc.topn,
    topm: desc.topm,
    query: desc.query,
  });

  const filas = await esperarReporte(baseUrl, target.apiKey, jobId, {
    onEspera: (intento) => {
      if (intento % 5 === 0) log(`  esperando al equipo (${intento})...`);
    },
  });

  onProgreso(2, 3);

  if (!filas.length) {
    log(
      "El reporte no devolvio filas. Puede que no haya trafico en el periodo, " +
        "o que la query del reporte no coincida con ninguna politica.",
      "warn"
    );
    return { resumen: [], alertas: [], descripcion: desc };
  }

  log(`${filas.length} fila(s) recibidas. Columnas: ${Object.keys(filas[0]).join(", ")}.`, "debug");

  if (!tieneColumnaRegla(filas)) {
    throw new Error(
      "El reporte no trae columna de regla, asi que no se puede atribuir el trafico por " +
        "politica. Recrealo con 'aggregate-by [ rule app dport dst src ]'."
    );
  }

  // --- 3. Agrupacion por politica ---
  const porRegla = agruparReportePorRegla(filas, reglas);
  log(`${porRegla.size} politica(s) con trafico en el reporte.`);

  if (reglas?.length) {
    const ausentes = reglas.filter((r) => !porRegla.has(r));
    if (ausentes.length) {
      log(
        `Sin trafico en el reporte para: ${ausentes.join(", ")}. ` +
          `Revisa que la query del reporte las incluya y que el periodo las cubra.`,
        "warn"
      );
    }
  }

  const resumen = [];
  const alertas = [];

  for (const [regla, datos] of [...porRegla.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const apps = [...datos.apps].sort();
    resumen.push({
      Politica: regla,
      "Total Apps": apps.length,
      "Aplicaciones Recomendadas": apps.join(" ") || "N/A",
      "Apps Alerta": [...datos.alerta].sort().join(" "),
      Sesiones: datos.sesiones,
      Origen: `report:${desc.nombre}`,
      Timestamp: fechaPanOs(new Date()),
      _apps: apps,
    });

    if (!apps.length) {
      alertas.push(`[ADVERTENCIA] '${regla}': el reporte no dejo ninguna aplicacion recomendable.`);
    }
    for (const a of [...datos.alerta].sort()) {
      alertas.push(
        `[ADVERTENCIA] '${regla}': trafico '${a}' detectado. Revision manual ` +
          `(SSL decryption, App-ID cloud) antes de cerrar la politica.`
      );
    }

    log(
      `${regla}: ${apps.length} app(s) recomendadas, ${datos.sesiones} sesion(es)` +
        (datos.alerta.size ? `, ${datos.alerta.size} de alerta.` : "."),
      apps.length ? "ok" : "warn"
    );
  }

  // --- exportacion opcional ---
  if (descargarCsv && resumen.length) {
    const marca = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    const ruta = `${CARPETA_RAIZ}/hardening/${nombreEquipo}_${marca}_reporte.csv`;
    await descargarTexto(aCsv(resumen.map(({ _apps, ...resto }) => resto)), ruta);
    log(`CSV resumen en Descargas/${ruta}`, "ok");
  }

  for (const a of alertas) log(a, "warn");

  log(
    `Finalizado desde reporte. ${resumen.length} politica(s), ${alertas.length} alerta(s). ` +
      `Recuerda: el topn del reporte limita la muestra.`,
    "ok"
  );

  onProgreso(3, 3);
  return { resumen, alertas, descripcion: desc };
}

/**
 * Flujo completo automatico: arma el reporte con las politicas indicadas,
 * opcionalmente lo guarda en el equipo, lo ejecuta y devuelve las apps por
 * politica listas para clonar.
 *
 * Sobre "crear el reporte":
 *  - Para OBTENER LOS DATOS no hace falta crear nada. El reporte se ejecuta
 *    ad hoc (reporttype=dynamic) con la definicion armada al vuelo, y eso
 *    funciona sin commit.
 *  - `guardarDefinicion: true` ademas escribe la definicion en la CANDIDATE
 *    config para que quede visible en Monitor > Manage Custom Reports. Esa
 *    escritura necesita un COMMIT MANUAL para persistir; la extension no lo
 *    hace. Si vuelves a ejecutar con el mismo nombre, se sobreescribe.
 *
 * @param {{target, reglas: string[], nombreReporte?, containerXpath?,
 *          periodo?, topn?, guardarDefinicion?, descargarCsv?}} config
 */
export async function ejecutarHardeningAutoReporte(config, log, onProgreso) {
  const {
    target,
    reglas,
    nombreReporte = "PAN-Helper-AppID",
    containerXpath = XPATH_REPORTES_SHARED,
    periodo = "last-90-calendar-days",
    topn = 500,
    guardarDefinicion = false,
    descargarCsv = false,
  } = config;

  if (!reglas?.length) {
    throw new Error(
      "Indica al menos una politica: el reporte se construye filtrando por sus nombres."
    );
  }

  const baseUrl = baseUrlFor(target);
  const totalPasos = guardarDefinicion ? 4 : 3;
  let paso = 0;

  const info = await getSystemInfo(baseUrl, target.apiKey);
  const nombreEquipo = nombreSeguro(info.devicename || info.hostname || target.host);
  log(`Conectado a ${nombreEquipo} (${info.model}, PAN-OS ${info.swVersion}).`, "ok");

  // --- 1. Construccion de la definicion ---
  const query = construirQueryReglas(reglas);
  const typeXml = construirTypeTrsum();

  log(`Reporte armado para ${reglas.length} politica(s): ${reglas.join(", ")}.`);
  log(`Query: ${query}`, "debug");
  log(`Periodo ${periodo}, topn ${topn}, agregado por rule/app/dport/dst/src.`);
  onProgreso(++paso, totalPasos);

  // --- 2. Guardado opcional de la definicion (unica escritura de config) ---
  if (guardarDefinicion) {
    log(
      `Guardando la definicion como '${nombreReporte}' en ${containerXpath} ` +
        `(candidate config)...`,
      "warn"
    );
    await guardarDefinicionReporte(baseUrl, target.apiKey, {
      nombre: nombreReporte,
      containerXpath,
      periodo,
      topn,
      topm: 25,
      query,
    });
    log(
      `'${nombreReporte}' guardado. Queda en la CANDIDATE config: haz commit en la GUI ` +
        `para que aparezca de forma permanente en Monitor > Manage Custom Reports.`,
      "ok"
    );
    onProgreso(++paso, totalPasos);
  }

  // --- 3. Ejecucion ad hoc (no depende del guardado ni del commit) ---
  log("Ejecutando el reporte...");
  const jobId = await ejecutarReporteAdHoc(baseUrl, target.apiKey, typeXml, {
    periodo,
    topn,
    topm: 25,
    query,
  });

  const filas = await esperarReporte(baseUrl, target.apiKey, jobId, {
    onEspera: (intento) => {
      if (intento % 5 === 0) log(`  esperando al equipo (${intento})...`);
    },
  });
  onProgreso(++paso, totalPasos);

  if (!filas.length) {
    log(
      "El reporte no devolvio filas. Puede que esas politicas no tengan trafico en el " +
        "periodo, o que los nombres no coincidan exactamente con los del rulebase.",
      "warn"
    );
    return { resumen: [], alertas: [] };
  }

  log(`${filas.length} fila(s) recibidas. Columnas: ${Object.keys(filas[0]).join(", ")}.`, "debug");

  if (!tieneColumnaRegla(filas)) {
    throw new Error(
      "El reporte no devolvio columna de regla; no se puede atribuir el trafico por " +
        "politica. Puede ser una diferencia de esta version de PAN-OS con trsum."
    );
  }

  // --- 4. Agrupacion ---
  const porRegla = agruparReportePorRegla(filas, reglas);
  const resumen = [];
  const alertas = [];

  const ausentes = reglas.filter((r) => !porRegla.has(r));
  if (ausentes.length) {
    log(
      `Sin trafico en el reporte para: ${ausentes.join(", ")}. Verifica el nombre exacto ` +
        `de la politica y que haya trafico permitido en el periodo.`,
      "warn"
    );
  }

  for (const [regla, datos] of [...porRegla.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const apps = [...datos.apps].sort();
    resumen.push({
      Politica: regla,
      "Total Apps": apps.length,
      "Aplicaciones Recomendadas": apps.join(" ") || "N/A",
      "Apps Alerta": [...datos.alerta].sort().join(" "),
      Sesiones: datos.sesiones,
      Origen: guardarDefinicion ? `report:${nombreReporte}` : "report:ad-hoc",
      Timestamp: fechaPanOs(new Date()),
      _apps: apps,
    });

    if (!apps.length) {
      alertas.push(`[ADVERTENCIA] '${regla}': el reporte no dejo ninguna aplicacion recomendable.`);
    }
    for (const a of [...datos.alerta].sort()) {
      alertas.push(
        `[ADVERTENCIA] '${regla}': trafico '${a}' detectado. Revision manual ` +
          `(SSL decryption, App-ID cloud) antes de cerrar la politica.`
      );
    }

    log(
      `${regla}: ${apps.length} app(s) recomendadas, ${datos.sesiones} sesion(es)` +
        (datos.alerta.size ? `, ${datos.alerta.size} de alerta.` : "."),
      apps.length ? "ok" : "warn"
    );
  }

  if (descargarCsv && resumen.length) {
    const marca = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    const ruta = `${CARPETA_RAIZ}/hardening/${nombreEquipo}_${marca}_reporte.csv`;
    await descargarTexto(aCsv(resumen.map(({ _apps, ...resto }) => resto)), ruta);
    log(`CSV resumen en Descargas/${ruta}`, "ok");
  }

  for (const a of alertas) log(a, "warn");

  log(
    `Finalizado. ${resumen.length} politica(s) con datos. Revisa las apps y usa ` +
      `"Clonar y ajustar" para crear las reglas endurecidas. Recuerda que el topn ` +
      `(${topn}) limita la muestra.`,
    "ok"
  );

  return { resumen, alertas };
}

// ---------------------------------------------------------------------------
//  Clonar y ajustar (Fase 2 del script original, via REST API)
// ---------------------------------------------------------------------------

export const SUFIJO_NUEVA_REGLA = "-AppID";

// Limite de PAN-OS para el nombre de una regla de security. Si el nombre
// original + sufijo lo supera, el firewall rechaza la creacion, asi que se
// detecta antes de escribir.
const MAX_LARGO_NOMBRE_REGLA = 63;

// Metadata que devuelve el GET de la regla pero que NO debe reenviarse al
// escribirla (igual que CAMPOS_A_QUITAR de los scripts; el de Panorama
// agrega @device-group).
const CAMPOS_A_QUITAR = ["@uuid", "@location", "@vsys", "@device-group", "@loc"];

/** Miembros de un campo <member> del JSON REST, normalizados a array. */
function miembros(campo) {
  const m = campo?.member;
  if (m === undefined || m === null) return [];
  return Array.isArray(m) ? [...m] : [m];
}

/**
 * Para cada politica seleccionada: clona la regla original, reemplaza el
 * campo application por las apps descubiertas, crea "<Politica><sufijo>" en
 * la CANDIDATE config y la mueve justo antes de la original.
 *
 * Si la regla con sufijo YA existe, hace merge: compara sus aplicaciones
 * actuales con las recien descubiertas y, si hay nuevas, actualiza la regla
 * con la union (PUT). Si no hay nada nuevo, no la toca. Portado de
 * procesar_politica() del script de Panorama; sirve para volver a correr el
 * analisis semanas despues y recoger las apps que aparecieron entre tanto.
 *
 * La regla ORIGINAL nunca se modifica: el PUT solo se aplica a un nombre
 * que termina con el sufijo, y se verifica antes de llamar.
 *
 * NO HACE COMMIT — no existe esa capacidad en la extension. El usuario
 * revisa las reglas en la GUI y hace commit (y en Panorama, el push al
 * device-group) manualmente.
 *
 * @param {{target, seleccion: Array<{regla, apps}>, sufijo?: string,
 *          vsys?: string|null, deviceGroup?: string|null,
 *          rulebase?: "pre"|"post"}} config
 * @param {(mensaje: string, nivel?: string) => void} log
 * @param {(hechos: number, total: number) => void} onProgreso
 * @returns {{creadas: number, actualizadas: number, sinCambios: number}}
 */
export async function clonarYAjustar(config, log, onProgreso) {
  const { target, vsys, deviceGroup, rulebase, seleccion } = config;
  const sufijo = (config.sufijo || "").trim() || SUFIJO_NUEVA_REGLA;

  if (!seleccion?.length) {
    throw new Error("No se selecciono ninguna politica para clonar.");
  }

  const esPanorama = /panorama/i.test(target.platform || "");
  let destino;

  if (esPanorama) {
    if (!deviceGroup) {
      throw new Error("Indica el device-group: en Panorama las reglas viven dentro de uno.");
    }
    destino = { tipo: rulebase === "pre" ? "pre" : "post", deviceGroup };
  } else {
    destino = { tipo: "vsys", vsys: vsys || "vsys1" };
  }

  const version = restVersionFromSw(target.swVersion);

  if (esPanorama) {
    log(
      `Clonar y ajustar: REST API ${version} en ${target.host}, device-group ` +
        `'${deviceGroup}', ${destino.tipo}-rulebase.`
    );
  } else {
    log(`Clonar y ajustar: REST API ${version} en ${target.host}, vsys '${destino.vsys}'.`);
    if (!vsys) log("Sin vsys indicado en el formulario: se usa 'vsys1'.", "warn");
  }

  log(`Sufijo de las reglas nuevas: '${sufijo}'.`);
  log(
    "Las reglas quedan en la CANDIDATE config. NO se hara commit: revisalas en la GUI y " +
      (esPanorama
        ? "haz commit a Panorama + push al device-group manualmente."
        : "haz commit manualmente."),
    "warn"
  );

  let hechos = 0;
  let creadas = 0;
  let actualizadas = 0;
  let sinCambios = 0;

  for (const { regla, apps } of seleccion) {
    try {
      // Filtro de seguridad, igual que construir_regla_appid del script:
      // cualquier ruido/alerta que se haya colado en la lista se descarta.
      const appsFiltradas = [...new Set(apps)]
        .filter((a) => !APLICACIONES_RUIDO.has(a) && !APLICACIONES_ALERTA.has(a))
        .sort();
      const descartadas = [...new Set(apps)].filter((a) => !appsFiltradas.includes(a));
      if (descartadas.length) {
        log(`${regla}: se descartaron apps de ruido/alerta: ${descartadas.sort().join(", ")}`, "warn");
      }
      if (!appsFiltradas.length) {
        log(`${regla}: tras filtrar ruido/alerta no queda ninguna app valida. Se omite.`, "error");
        continue;
      }

      const nuevoNombre = `${regla}${sufijo}`;
      if (nuevoNombre.length > MAX_LARGO_NOMBRE_REGLA) {
        log(
          `${regla}: '${nuevoNombre}' supera los ${MAX_LARGO_NOMBRE_REGLA} caracteres que ` +
            `admite PAN-OS. Usa un sufijo mas corto. Se omite.`,
          "error"
        );
        continue;
      }
      // Garantia de que el PUT nunca pueda caer sobre la regla original.
      if (!nuevoNombre.endsWith(sufijo) || nuevoNombre === regla) {
        log(`${regla}: el sufijo no produce un nombre distinto. Se omite.`, "error");
        continue;
      }

      const existente = await obtenerReglaSecurity(target, destino, nuevoNombre);

      if (existente) {
        // --- merge: agregar solo las apps que aun no estan ---
        const actuales = miembros(existente.application);
        const nuevas = appsFiltradas.filter((a) => !actuales.includes(a));

        if (!nuevas.length) {
          log(`${nuevoNombre}: ya existe y no hay aplicaciones nuevas. No se modifica.`);
          sinCambios++;
        } else {
          const union = [...new Set([...actuales, ...appsFiltradas])].sort();
          const actualizada = JSON.parse(JSON.stringify(existente));
          for (const campo of CAMPOS_A_QUITAR) delete actualizada[campo];
          actualizada["@name"] = nuevoNombre;
          actualizada.application = { member: union };

          await actualizarReglaSecurity(target, destino, nuevoNombre, actualizada);
          log(
            `${nuevoNombre}: actualizada con ${nuevas.length} app(s) nueva(s) ` +
              `(${nuevas.join(", ")}); ahora tiene ${union.length}.`,
            "ok"
          );
          actualizadas++;
        }
      } else {
        // --- creacion: clon de la original con el application reemplazado ---
        log(`${regla}: leyendo la regla original...`, "debug");
        const original = await obtenerReglaSecurity(target, destino, regla);
        if (!original) {
          log(
            `${regla}: la regla original no existe en ` +
              (esPanorama
                ? `el ${destino.tipo}-rulebase del device-group '${deviceGroup}'.`
                : `vsys '${destino.vsys}'.`),
            "error"
          );
          continue;
        }

        const nueva = JSON.parse(JSON.stringify(original));
        for (const campo of CAMPOS_A_QUITAR) delete nueva[campo];
        nueva["@name"] = nuevoNombre;
        nueva.application = { member: appsFiltradas };

        await crearReglaSecurity(target, destino, nuevoNombre, nueva);
        log(`${nuevoNombre}: creada en la candidate config (${appsFiltradas.length} apps).`, "ok");
        creadas++;
      }

      await moverReglaAntesDe(target, destino, nuevoNombre, regla);
      log(`${nuevoNombre}: movida antes de '${regla}'.`, "ok");
    } catch (e) {
      log(`${regla}: ${e.message}`, "error");
      if (e.name === "OperacionCanceladaError") break;
    } finally {
      onProgreso(++hechos, seleccion.length);
    }
  }

  log(
    `Clonado finalizado: ${creadas} creada(s), ${actualizadas} actualizada(s), ` +
      `${sinCambios} sin cambios, de ${seleccion.length} seleccionada(s). ` +
      (esPanorama
        ? "Recuerda REVISAR, hacer COMMIT a Panorama y PUSH al device-group manualmente."
        : "Recuerda REVISAR y hacer COMMIT manualmente en la GUI del firewall."),
    creadas + actualizadas ? "ok" : "warn"
  );

  return { creadas, actualizadas, sinCambios };
}

// js/modules/apikeys.js
// Modulo: generacion masiva de API keys.
// Port de generador-apikeys-masivo/api-keys_concurrente.py
//
// Por cada equipo: cambia usuario/contrasena por una API key (keygen) y con
// esa key consulta 'show system info' para sacar hostname, serial, modelo y
// version. El resultado se descarga como CSV.
//
// Diferencias deliberadas con el script original:
//
//  - Las credenciales NO se leen de un archivo en disco. El caso normal es
//    pegar el rango directamente desde Excel: nunca se guarda un archivo con
//    contrasenas. (El script leia PA_PASS.xlsx con las claves en texto plano.)
//  - El CSV de salida NO incluye la columna de contrasena. El original hacia
//    concat del archivo de entrada con los resultados, asi que el archivo
//    final tenia contrasenas Y api keys juntas.
//  - Concurrencia acotada a 4. El original usaba ThreadPoolExecutor sin
//    limite: con 31 equipos abria 31 conexiones simultaneas.
//  - keygen va por POST con la contrasena en el cuerpo. El original la ponia
//    en la URL (?type=keygen&user=..&password=..), que queda en los logs del
//    servidor web del propio equipo y en cualquier proxy intermedio.
//  - Los fallos por certificado se separan del resto: son los unicos que se
//    resuelven abriendo el host en una pestana, y conviene listarlos aparte.
//
// SOLO LECTURA: keygen y 'show system info' no modifican nada. El candado de
// panApi.js no necesita excepciones para este modulo.

import { baseUrlFor, keygen, getSystemInfo } from "../lib/panApi.js";
import { ejecutarEnLote, aCsv, descargarTexto, nombreSeguro } from "../lib/util.js";

const CONCURRENCIA = 4;
const CARPETA_RAIZ = "PAN-Helper";

// ---------------------------------------------------------------------------
//  Parser de credenciales (pegado desde Excel o archivo CSV)
// ---------------------------------------------------------------------------

// Nombres aceptados por columna. Se comparan en minusculas y sin acentos,
// para que de igual "Contrasena", "Contrasena" con tilde o "CONTRASENA".
const ALIAS = {
  cliente: ["cliente", "client", "customer", "empresa", "nombre"],
  host: ["ip", "host", "hostname", "direccion", "equipo", "firewall", "fqdn"],
  usuario: ["user", "usuario", "username", "login", "admin"],
  password: ["pass", "password", "contrasena", "clave", "secret"],
};

const normalizar = (s) =>
  String(s || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "");

/**
 * Detecta el separador contando cual aparece de forma mas consistente en las
 * primeras lineas. Excel copia con tabulacion; un CSV puede venir con coma o
 * con punto y coma (Excel en configuracion regional espanola).
 */
function detectarSeparador(texto) {
  const lineas = texto.trim().split(/\r?\n/).slice(0, 5).filter(Boolean);
  if (!lineas.length) return ",";

  let mejor = ",";
  let mejorPuntaje = -1;

  for (const sep of ["\t", ";", ","]) {
    const cuentas = lineas.map((l) => l.split(sep).length);
    // Buena senal: mas de una columna y el mismo numero en todas las lineas.
    const consistente = cuentas.every((c) => c === cuentas[0]);
    const puntaje = cuentas[0] > 1 ? cuentas[0] * (consistente ? 10 : 1) : 0;
    if (puntaje > mejorPuntaje) {
      mejorPuntaje = puntaje;
      mejor = sep;
    }
  }
  return mejor;
}

/** Divide una linea respetando comillas dobles. */
function dividirLinea(linea, sep) {
  const campos = [];
  let campo = "";
  let enComillas = false;

  for (let i = 0; i < linea.length; i++) {
    const c = linea[i];
    if (enComillas) {
      if (c === '"') {
        if (linea[i + 1] === '"') { campo += '"'; i++; }
        else enComillas = false;
      } else campo += c;
    } else if (c === '"') {
      enComillas = true;
    } else if (c === sep) {
      campos.push(campo); campo = "";
    } else {
      campo += c;
    }
  }
  campos.push(campo);
  return campos.map((f) => f.trim());
}

/**
 * Texto tabular -> matriz de celdas, detectando el separador solo.
 * La usa tanto el parser como el pegado en la cuadricula.
 */
export function dividirTabla(texto) {
  const limpio = String(texto || "").replace(/^﻿/, "");
  const sep = detectarSeparador(limpio);
  const filas = limpio
    .split(/\r?\n/)
    .filter((l) => l.trim() !== "")
    .map((l) => dividirLinea(l, sep));
  return { filas, separador: sep };
}

/** Orden de las columnas de la cuadricula, para el pegado posicional. */
export const CAMPOS_GRID = ["cliente", "host", "usuario", "password"];

/**
 * Mapea texto tabular a filas de la cuadricula SIN validar ni descartar
 * nada. A diferencia de parsearCredenciales(), aqui una fila a medias tiene
 * que llegar igual: la cuadricula debe mostrarla para que el usuario la
 * complete, en vez de hacerla desaparecer sin que se entere.
 *
 * @returns {{filas, conCabecera, separador}}
 */
export function mapearTablaAGrid(texto) {
  const { filas, separador } = dividirTabla(texto);
  if (!filas.length) return { filas: [], conCabecera: false, separador };

  const posibleMapa = mapearCabecera(filas[0]);
  const conCabecera = Object.values(posibleMapa).filter((i) => i >= 0).length >= 2;
  const mapeo = conCabecera ? posibleMapa : { cliente: 0, host: 1, usuario: 2, password: 3 };

  const cuerpo = conCabecera ? filas.slice(1) : filas;

  return {
    filas: cuerpo.map((fila) => {
      const v = {};
      for (const campo of CAMPOS_GRID) {
        const i = mapeo[campo];
        v[campo] = i >= 0 && i < fila.length ? fila[i].trim() : "";
      }
      v.host = v.host.replace(/^https?:\/\//, "").replace(/\/$/, "");
      return v;
    }),
    conCabecera,
    separador,
  };
}

/** Indice de la columna que corresponde a cada campo, o -1. */
function mapearCabecera(cabecera) {
  const normalizadas = cabecera.map(normalizar);
  const mapa = {};
  for (const [campo, alias] of Object.entries(ALIAS)) {
    mapa[campo] = normalizadas.findIndex((c) => alias.includes(c));
  }
  return mapa;
}

/** Plantilla CSV descargable, con valores de ejemplo evidentemente falsos. */
export function csvPlantilla() {
  return [
    "Cliente,IP,User,Pass",
    "Cliente-A,10.0.0.1,usuario,contrasena",
    "Cliente-A,10.0.0.2,usuario,contrasena",
    "Cliente-B,firewall.ejemplo.local,usuario,contrasena",
  ].join("\r\n");
}

// ---------------------------------------------------------------------------
//  Generacion
// ---------------------------------------------------------------------------

/** True si el fallo se resuelve aceptando el certificado en una pestana. */
function esFalloDeCertificado(error) {
  return /No se pudo conectar/i.test(error?.message || "");
}

async function procesarEquipo(equipo) {
  const baseUrl = baseUrlFor({ host: equipo.host, port: 443 });

  const apiKey = await keygen(baseUrl, equipo.usuario, equipo.password);
  const info = await getSystemInfo(baseUrl, apiKey);

  return {
    hostname: info.devicename || info.hostname || "",
    serial: info.serial || "",
    modelo: info.model || "",
    version: info.swVersion || "",
    apiKey,
  };
}

/**
 * Punto de entrada del modulo.
 *
 * @param {{equipos: Array<{cliente, host, usuario, password}>,
 *          descargarCsv?: boolean}} config
 * @param {(mensaje: string, nivel?: string) => void} log
 * @param {(hechos: number, total: number) => void} onProgreso
 * @returns {{filas, fallosCertificado, ok, error}}
 */
export async function generarApiKeys(config, log, onProgreso) {
  const { equipos, descargarCsv = true } = config;

  if (!equipos?.length) {
    throw new Error("No hay equipos que procesar.");
  }

  log(`${equipos.length} equipo(s), hasta ${CONCURRENCIA} en paralelo.`);
  log(
    "Las contrasenas se usan solo para pedir la API key: no se guardan en " +
      "ningun lado ni salen en el CSV.",
    "ok"
  );

  const marcaTiempo = new Date().toISOString().slice(0, 19).replace("T", " ");
  let hechos = 0;

  const resultados = await ejecutarEnLote(equipos, CONCURRENCIA, async (equipo) => {
    try {
      log(`${equipo.host}: solicitando API key...`, "debug");
      const datos = await procesarEquipo(equipo);
      log(
        `${equipo.host}: OK - ${datos.hostname} (${datos.modelo}, PAN-OS ${datos.version})`,
        "ok"
      );
      return datos;
    } finally {
      onProgreso(++hechos, equipos.length);
    }
  });

  const filas = [];
  const fallosCertificado = [];
  let ok = 0;
  let error = 0;

  resultados.forEach((r, i) => {
    const equipo = equipos[i];
    const base = {
      Cliente: equipo.cliente || "",
      IP: equipo.host,
      Usuario: equipo.usuario,
    };

    if (r.ok) {
      ok++;
      filas.push({
        ...base,
        Hostname: r.valor.hostname,
        Serial: r.valor.serial,
        Modelo: r.valor.modelo,
        Version: r.valor.version,
        ApiKey: r.valor.apiKey,
        Estado: "OK",
        Timestamp: marcaTiempo,
      });
    } else {
      error++;
      const certificado = esFalloDeCertificado(r.error);
      if (certificado) fallosCertificado.push(equipo.host);

      log(`${equipo.host}: ${r.error.message}`, "error");
      filas.push({
        ...base,
        Hostname: "",
        Serial: "",
        Modelo: "",
        Version: "",
        ApiKey: "",
        Estado: certificado ? "ERROR - certificado no aceptado" : `ERROR - ${r.error.message}`,
        Timestamp: marcaTiempo,
      });
    }
  });

  if (fallosCertificado.length) {
    log(
      `${fallosCertificado.length} equipo(s) fallaron porque su certificado no ha sido ` +
        `aceptado en este navegador. Abrelos en una pestana, acepta la advertencia y ` +
        `vuelve a ejecutar: ${fallosCertificado.join(", ")}`,
      "warn"
    );
  }

  if (descargarCsv) {
    const marca = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    const ruta = `${CARPETA_RAIZ}/apikeys/ApiKeys_${nombreSeguro(marca)}.csv`;
    await descargarTexto(aCsv(filas), ruta);
    log(`CSV en Descargas/${ruta}`, "ok");
    log(
      "ATENCION: ese archivo contiene API keys, que dan el mismo acceso que la " +
        "credencial. Guardalo donde corresponda y borralo cuando ya no lo necesites.",
      "warn"
    );
  }

  log(`Finalizado. ${ok} exitoso(s), ${error} con error.`, error ? "warn" : "ok");

  return { filas, fallosCertificado, ok, error };
}

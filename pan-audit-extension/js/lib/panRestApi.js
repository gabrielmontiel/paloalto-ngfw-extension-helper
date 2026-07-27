// js/lib/panRestApi.js
// Cliente REST de PAN-OS (https://<host>/restapi/vX.Y/...), portado de la
// Fase 2 de analizadorAppId-REST.py.
//
// ESCRITURA ACOTADA — este es el UNICO archivo de la extension que puede
// escribir en el equipo, y solo puede hacer estas cosas:
//
//   1. Leer una regla de security (GET).
//   2. Crear una regla de security (POST)   — la clonada "-AppID".
//   3. Mover una regla de security (POST :move).
//   4. Actualizar una regla de security (PUT) — solo la clonada con sufijo,
//      para agregarle aplicaciones nuevas en una corrida posterior. El
//      modulo que la llama verifica que el nombre lleve el sufijo: la regla
//      original nunca se toca.
//   5. Leer, actualizar (PUT) y eliminar (DELETE) un objeto address /
//      address-group / service / service-group. El PUT solo se usa para
//      quitarle miembros a un grupo antes de borrar esos miembros.
//
// Un guard de endpoint rechaza cualquier otra ruta antes de tocar la red, y
// DELETE solo se admite sobre los endpoints de Objects: NINGUNA regla se
// elimina nunca.
//
// Funciona igual contra un firewall (location=vsys, SecurityRules) y contra
// Panorama (location=device-group, SecurityPreRules / SecurityPostRules).
// AQUI NO EXISTE COMMIT: no hay funcion, endpoint ni parametro que lo haga.
// Todo lo escrito queda en la CANDIDATE config; el commit es siempre manual,
// previa revision en la GUI del firewall.
//
// El cliente XML (panApi.js) conserva su candado de solo lectura intacto:
// este modulo no lo usa ni lo modifica.

import { baseUrlFor, senalDeCancelacion, OperacionCanceladaError } from "./panApi.js";

// Rutas permitidas. Cualquier otra se rechaza antes de tocar la red.
// SecurityRules = firewall (vsys); SecurityPreRules / SecurityPostRules =
// Panorama (pre y post rulebase de un device-group).
const ENDPOINT_REGLAS =
  /^\/restapi\/v\d+\.\d+\/Policies\/Security(Pre|Post)?Rules(:move)?$/;
const ENDPOINT_OBJETOS =
  /^\/restapi\/v\d+\.\d+\/Objects\/(Addresses|AddressGroups|Services|ServiceGroups)$/;

// Tipo de objeto (como lo reporta la auditoria) -> endpoint REST.
const ENDPOINT_POR_TIPO = {
  address: "Addresses",
  "address-group": "AddressGroups",
  service: "Services",
  "service-group": "ServiceGroups",
};

/**
 * Deriva la version del endpoint REST desde la version de PAN-OS guardada
 * en la conexion (p. ej. "10.2.4-h2" -> "v10.2"). El REST API exige que la
 * version de la URL coincida con la del equipo.
 */
export function restVersionFromSw(swVersion) {
  const m = String(swVersion || "").match(/^(\d+)\.(\d+)/);
  if (!m) {
    throw new Error(
      `No se pudo derivar la version del REST API desde PAN-OS '${swVersion}'. ` +
        `Reconecta el equipo en Conexiones para refrescar su version.`
    );
  }
  return `v${m[1]}.${m[2]}`;
}

// Recurso REST del rulebase segun la plataforma y, en Panorama, si se
// trabaja el pre o el post rulebase del device-group.
const RECURSO_RULEBASE = {
  vsys: "SecurityRules",
  pre: "SecurityPreRules",
  post: "SecurityPostRules",
};

/**
 * Describe donde viven las reglas con las que se va a trabajar.
 *
 * Firewall:  { tipo: "vsys", vsys: "vsys4" }
 * Panorama:  { tipo: "pre"|"post", deviceGroup: "DG-Sucursales" }
 */
export function ubicacionReglas(destino) {
  if (destino?.tipo === "vsys") {
    if (!destino.vsys) throw new Error("Falta el vsys para ubicar las reglas.");
    return { recurso: RECURSO_RULEBASE.vsys, params: { location: "vsys", vsys: destino.vsys } };
  }
  if (destino?.tipo === "pre" || destino?.tipo === "post") {
    if (!destino.deviceGroup) {
      throw new Error("Falta el device-group para ubicar las reglas en Panorama.");
    }
    return {
      recurso: RECURSO_RULEBASE[destino.tipo],
      params: { location: "device-group", "device-group": destino.deviceGroup },
    };
  }
  throw new Error(`Ubicacion de reglas no soportada: '${destino?.tipo}'.`);
}

function rutaSecurityRules(target, destino, accion = "") {
  const { recurso } = ubicacionReglas(destino);
  return `/restapi/${restVersionFromSw(target.swVersion)}/Policies/${recurso}${accion}`;
}

async function restCall(target, ruta, { method = "GET", params = {}, body = null } = {}) {
  const esRegla = ENDPOINT_REGLAS.test(ruta);
  const esObjeto = ENDPOINT_OBJETOS.test(ruta);

  if (!esRegla && !esObjeto) {
    throw new Error(`Endpoint REST no permitido por la extension: ${ruta}`);
  }
  // NINGUNA regla se elimina nunca. El DELETE solo existe para objetos.
  if (method === "DELETE" && !esObjeto) {
    throw new Error(`La extension no puede eliminar en ${ruta}: DELETE solo aplica a objetos.`);
  }

  const url = new URL(baseUrlFor(target) + ruta);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);

  let res;
  try {
    res = await fetch(url, {
      method,
      headers: { "X-PAN-KEY": target.apiKey, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
      signal: senalDeCancelacion(),
    });
  } catch (e) {
    if (e?.name === "AbortError") throw new OperacionCanceladaError();
    throw new Error(`No se pudo conectar con ${target.host} (REST): ${e.message}`);
  }

  const texto = await res.text();
  let data = null;
  try { data = texto ? JSON.parse(texto) : null; } catch { /* respuesta no-JSON */ }

  if (!res.ok) {
    // "Object Not Present" en un GET no es un error: la regla no existe.
    if (method === "GET" && res.status === 404) return null;
    const msg = data?.message || data?.msg || (texto || res.statusText).slice(0, 300);
    throw new Error(`REST HTTP ${res.status}: ${msg}`);
  }

  return data;
}

/**
 * GET de una regla de security. Devuelve el 'entry' o null si no existe.
 * @param {object} destino  ver ubicacionReglas()
 */
export async function obtenerReglaSecurity(target, destino, nombre) {
  const { params } = ubicacionReglas(destino);
  const data = await restCall(target, rutaSecurityRules(target, destino), {
    method: "GET",
    params: { ...params, name: nombre },
  });
  const entries = data?.result?.entry || [];
  return entries.length ? entries[0] : null;
}

/**
 * POST para crear una regla nueva en la CANDIDATE config. No hace commit.
 */
export async function crearReglaSecurity(target, destino, nombre, entryJson) {
  const { params } = ubicacionReglas(destino);
  return restCall(target, rutaSecurityRules(target, destino), {
    method: "POST",
    params: { ...params, name: nombre },
    body: { entry: entryJson },
  });
}

/**
 * PUT para reemplazar una regla EXISTENTE. Se usa solo para agregarle
 * aplicaciones nuevas a la regla clonada con sufijo; quien llama debe
 * verificar que el nombre lleve ese sufijo (la original nunca se toca).
 */
export async function actualizarReglaSecurity(target, destino, nombre, entryJson) {
  const { params } = ubicacionReglas(destino);
  return restCall(target, rutaSecurityRules(target, destino), {
    method: "PUT",
    params: { ...params, name: nombre },
    body: { entry: entryJson },
  });
}

/**
 * POST al endpoint :move. Segun la documentacion oficial, name / location /
 * vsys (o device-group) / where / dst van como QUERY PARAMETERS, no en el
 * body.
 */
export async function moverReglaAntesDe(target, destino, nombre, reglaReferencia) {
  const { params } = ubicacionReglas(destino);
  return restCall(target, rutaSecurityRules(target, destino, ":move"), {
    method: "POST",
    params: { ...params, name: nombre, where: "before", dst: reglaReferencia },
  });
}

// ---------------------------------------------------------------------------
//  Objetos (address / service) — lectura y borrado
// ---------------------------------------------------------------------------

/**
 * Traduce el ambito que reporta la auditoria a los parametros `location`
 * del REST API.
 *   shared        -> location=shared
 *   vsys          -> location=vsys&vsys=<nombre>
 *   device-group  -> location=device-group&device-group=<nombre>  (Panorama)
 */
export function paramsDeUbicacion(scopeKind, scopeName) {
  if (scopeKind === "shared") return { location: "shared" };
  if (scopeKind === "vsys") {
    if (!scopeName) throw new Error("Ambito vsys sin nombre; no se puede ubicar el objeto.");
    return { location: "vsys", vsys: scopeName };
  }
  if (scopeKind === "device-group") {
    if (!scopeName) throw new Error("Ambito device-group sin nombre; no se puede ubicar el objeto.");
    return { location: "device-group", "device-group": scopeName };
  }
  throw new Error(`Ambito no soportado para operar sobre objetos: '${scopeKind}'.`);
}

function rutaObjetos(target, tipo) {
  const endpoint = ENDPOINT_POR_TIPO[tipo];
  if (!endpoint) throw new Error(`Tipo de objeto no soportado: '${tipo}'.`);
  return `/restapi/${restVersionFromSw(target.swVersion)}/Objects/${endpoint}`;
}

/**
 * DELETE de un objeto en la CANDIDATE config. No hace commit.
 *
 * @param {object} target  conexion guardada
 * @param {{kind, name, scopeKind, scopeName}} objeto  tal como lo reporta la auditoria
 */
export async function eliminarObjeto(target, objeto) {
  return restCall(target, rutaObjetos(target, objeto.kind), {
    method: "DELETE",
    params: { ...paramsDeUbicacion(objeto.scopeKind, objeto.scopeName), name: objeto.name },
  });
}

/** GET de un objeto. Devuelve el 'entry' o null si no existe. */
export async function obtenerObjeto(target, objeto) {
  const data = await restCall(target, rutaObjetos(target, objeto.kind), {
    method: "GET",
    params: { ...paramsDeUbicacion(objeto.scopeKind, objeto.scopeName), name: objeto.name },
  });
  const entries = data?.result?.entry || [];
  return entries.length ? entries[0] : null;
}

/**
 * PUT de un objeto: reemplaza su definicion en la CANDIDATE config. Se usa
 * para quitarle miembros a un grupo antes de borrar esos miembros. No hace
 * commit.
 */
export async function actualizarObjeto(target, objeto, entryJson) {
  return restCall(target, rutaObjetos(target, objeto.kind), {
    method: "PUT",
    params: { ...paramsDeUbicacion(objeto.scopeKind, objeto.scopeName), name: objeto.name },
    body: { entry: entryJson },
  });
}

// ---------------------------------------------------------------------------
//  Membresia de grupos (JSON del REST API)
// ---------------------------------------------------------------------------

// Los address-group llevan sus miembros estaticos en <static>; los
// service-group en <members>. En el JSON del REST son las claves "static" y
// "members", cada una con { member: [...] }.
const CLAVE_MIEMBROS = { "address-group": "static", "service-group": "members" };

/** Lista de miembros de un entry de grupo devuelto por el REST API. */
export function miembrosDeGrupo(entry, kind) {
  const clave = CLAVE_MIEMBROS[kind];
  if (!clave) throw new Error(`'${kind}' no es un grupo.`);
  const contenedor = entry?.[clave];
  if (!contenedor) return null; // grupo dinamico (por tag) o sin miembros estaticos
  const m = contenedor.member;
  if (m === undefined || m === null) return [];
  return Array.isArray(m) ? [...m] : [m];
}

/**
 * Copia el entry del grupo dejando solo los miembros indicados, y sin la
 * metadata que el GET agrega pero el PUT no debe recibir.
 */
export function grupoConMiembros(entry, kind, miembros) {
  const clave = CLAVE_MIEMBROS[kind];
  if (!clave) throw new Error(`'${kind}' no es un grupo.`);
  const copia = JSON.parse(JSON.stringify(entry));
  for (const campo of ["@uuid", "@location", "@vsys", "@device-group", "@loc"]) {
    delete copia[campo];
  }
  copia[clave] = { member: [...miembros] };
  return copia;
}

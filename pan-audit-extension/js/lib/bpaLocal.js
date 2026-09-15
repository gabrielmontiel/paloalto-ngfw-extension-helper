// js/lib/bpaLocal.js
// Evaluacion LOCAL de buenas practicas sobre un running-config de PAN-OS o
// Panorama. No es el BPA oficial de Palo Alto: son checks propios de PAN Helper,
// evaluados en el navegador, sin enviar la configuracion a ningun lado.
//
// Produce el MISMO formato que devuelve SCM Posture API:
//   { information, best_practices: { <categoria>: { <area>: [ {configuration, warnings[]} ] } } }
// asi el resumen, el HTML y el Excel (bpaReport.js / bpaExcel.js) funcionan
// igual para los tres origenes. Cada warning trae check_id, check_name,
// check_type (Critical/Warning/Informational) y check_passed:
//   true = cumple, false = falla, null = no aplica / no se puede determinar.
//
// Ambitos que se recorren:
//   Firewall:  vsys (reglas, perfiles, zonas), shared (perfiles),
//              deviceconfig + mgt-config del propio equipo.
//   Panorama:  shared y device-groups (reglas, perfiles), templates (zonas,
//              administracion, updates) y deviceconfig + mgt-config del
//              propio Panorama.
// En un template, un valor ausente NO es una falla: el firewall puede tenerlo
// configurado localmente. Se reporta como "no aplica" con el motivo.
//
// Modulo puro: recibe el elemento <config> ya parseado; no usa red ni chrome.*.

import { children, child, memberList, entryName, textOf } from "./xmlUtils.js";
import { selloLocal } from "./bpaReport.js";

// ---------------------------------------------------------------------------
//  Catalogo de checks (ids estables: aparecen en el reporte y en el Excel)
// ---------------------------------------------------------------------------

const C = "Critical";
const W = "Warning";
const I = "Informational";

export const CHECKS_LOCALES = {
  A01: { tipo: C, nombre: "Evitar reglas allow con any en origen, destino, aplicación y servicio" },
  A02: { tipo: W, nombre: "Usar App-ID en lugar de application any" },
  A03: { tipo: W, nombre: "Usar service application-default o puertos definidos en lugar de any" },
  A04: { tipo: C, nombre: "Asignar perfiles de seguridad o un Security Profile Group" },
  A05: { tipo: W, nombre: "Registrar log al final de la sesión" },
  A06: { tipo: W, nombre: "Asignar un Log Forwarding profile" },
  A07: { tipo: I, nombre: "Documentar la regla con una descripción" },
  A08: { tipo: I, nombre: "Etiquetar la regla con tags" },
  A09: { tipo: W, nombre: "Registrar log en las reglas por defecto (intrazone/interzone)" },
  B10: { tipo: W, nombre: "Tener al menos una regla de descifrado activa" },
  B11: { tipo: W, nombre: "Asignar un Decryption profile a las reglas de descifrado" },
  B12: { tipo: W, nombre: "Decryption profile: exigir TLS 1.2 o superior" },
  B13: { tipo: W, nombre: "Decryption profile: bloquear certificados vencidos y de emisores no confiables" },
  C14: { tipo: W, nombre: "Antivirus: acción reset-both en todos los decoders" },
  C15: { tipo: W, nombre: "Antivirus: acción WildFire reset-both" },
  C16: { tipo: W, nombre: "Anti-Spyware: bloquear severidades crítica, alta y media" },
  C17: { tipo: C, nombre: "Anti-Spyware: DNS sinkhole para dominios maliciosos" },
  C18: { tipo: W, nombre: "Vulnerability Protection: bloquear severidades crítica y alta" },
  C19: { tipo: C, nombre: "URL Filtering: bloquear malware, phishing y command-and-control" },
  C20: { tipo: W, nombre: "URL Filtering: habilitar la prevención de robo de credenciales" },
  C21: { tipo: W, nombre: "File Blocking: bloquear tipos de archivo ejecutables peligrosos" },
  C22: { tipo: W, nombre: "WildFire: reenviar cualquier aplicación y tipo de archivo" },
  D23: { tipo: W, nombre: "Asignar un Zone Protection profile a la zona" },
  D24: { tipo: W, nombre: "Habilitar Packet Buffer Protection en la zona" },
  D25: { tipo: W, nombre: "Zone Protection: habilitar protección contra flood (SYN, UDP, ICMP)" },
  E26: { tipo: C, nombre: "Deshabilitar Telnet y HTTP para administración" },
  E27: { tipo: C, nombre: "Restringir la interfaz de gestión con IPs permitidas" },
  E28: { tipo: W, nombre: "Exigir complejidad de contraseñas (mínimo 12 caracteres)" },
  E29: { tipo: W, nombre: "Administradores locales con password profile o complejidad global" },
  E30: { tipo: W, nombre: "Eliminar o renombrar la cuenta admin por defecto" },
  E31: { tipo: I, nombre: "Superusuarios con authentication profile" },
  E32: { tipo: W, nombre: "Configurar el timeout de sesión inactiva (15 minutos o menos)" },
  E33: { tipo: W, nombre: "Bloquear la cuenta tras intentos fallidos de login" },
  E34: { tipo: I, nombre: "Configurar un banner de login" },
  E35: { tipo: W, nombre: "Configurar servidores NTP" },
  E36: { tipo: W, nombre: "Usar SNMP v3 en lugar de v2c" },
  E37: { tipo: W, nombre: "Reenviar los logs de sistema y configuración (syslog, Panorama u otro destino)" },
  F38: { tipo: W, nombre: "Programar Antivirus con download-and-install" },
  F39: { tipo: W, nombre: "Programar Aplicaciones y Amenazas con download-and-install" },
  F40: { tipo: W, nombre: "Programar WildFire en tiempo real o cada minuto" },
  G41: { tipo: I, nombre: "Configurar alta disponibilidad (HA)" },
  G42: { tipo: W, nombre: "HA: habilitar link monitoring (y path monitoring)" },
  G43: { tipo: W, nombre: "HA: mantener la sincronización de configuración" },
  H44: { tipo: C, nombre: "Renovar certificados vencidos" },
  H45: { tipo: W, nombre: "Renovar certificados que vencen en 90 días o menos" },
};

// Umbrales fijos (se documentan en el nombre del check).
export const UMBRALES = { passwordMinimo: 12, idleTimeoutMax: 15, diasCertificado: 90 };

const ACCIONES_BLOQUEO = new Set(["reset-both", "drop", "block-ip", "reset-client", "reset-server"]);
const DECODERS_AV = ["http", "http2", "smtp", "imap", "pop3", "ftp", "smb"];
const URL_CATEGORIAS_BLOQUEO = ["malware", "phishing", "command-and-control"];
const TIPOS_ARCHIVO_PELIGROSOS = ["PE", "bat", "cpl", "hta", "jar", "pif", "scr", "vbe", "wsf"];

// ---------------------------------------------------------------------------
//  Utilidades
// ---------------------------------------------------------------------------

/** child() encadenado: ruta(el, "deviceconfig/system/hostname") */
function ruta(el, camino) {
  let actual = el;
  for (const tag of camino.split("/")) {
    if (!actual) return null;
    actual = child(actual, tag);
  }
  return actual;
}

const texto = (el, camino) => textOf(ruta(el, camino));
const entradas = (el, camino) => children(ruta(el, camino), "entry");
const esAny = (lista) => lista.length === 0 || (lista.length === 1 && lista[0] === "any");

/** Un warning del BPA. pasa: true | false | null. */
function w(id, pasa, mensaje = "") {
  const c = CHECKS_LOCALES[id];
  return {
    check_id: `LOC-${id}`,
    check_name: c.nombre,
    check_type: c.tipo,
    check_passed: pasa,
    check_excluded: false,
    user_excluded: false,
    check_message: mensaje || null,
  };
}

function agregar(bp, categoria, area, configuration, warnings) {
  bp[categoria] ||= {};
  bp[categoria][area] ||= [];
  bp[categoria][area].push({ configuration, warnings });
}

// ---------------------------------------------------------------------------
//  Ambitos
// ---------------------------------------------------------------------------

function modelo(config) {
  const shared = child(config, "shared");
  const dispositivo = children(child(config, "devices"), "entry")[0] || null;
  const panorama = Boolean(child(config, "panorama") || child(dispositivo, "device-group"));

  // Donde viven reglas y perfiles.
  const politicas = panorama
    ? [
        { loc: "shared", el: shared, esShared: true },
        ...children(child(dispositivo, "device-group"), "entry").map((e) => ({ loc: entryName(e), el: e })),
      ]
    : children(child(dispositivo, "vsys"), "entry").map((e) => ({ loc: entryName(e), el: e }));

  const contenedoresPerfiles = panorama ? politicas : [{ loc: "shared", el: shared }, ...politicas];

  // Donde viven zonas, perfiles de red, deviceconfig y mgt-config.
  const equipos = [];
  if (panorama) {
    equipos.push({ loc: "Panorama", dispositivo, config, plantilla: false });
    for (const t of children(child(dispositivo, "template"), "entry")) {
      const tconfig = child(t, "config");
      if (!tconfig) continue;
      equipos.push({
        loc: entryName(t),
        dispositivo: children(child(tconfig, "devices"), "entry")[0] || null,
        config: tconfig,
        plantilla: true,
      });
    }
  } else {
    equipos.push({ loc: texto(dispositivo, "deviceconfig/system/hostname") || "firewall", dispositivo, config, plantilla: false });
  }

  return { panorama, shared, dispositivo, politicas, contenedoresPerfiles, equipos };
}

// ---------------------------------------------------------------------------
//  A. Reglas de seguridad
// ---------------------------------------------------------------------------

function rulebasesDe(ambito) {
  const out = [];
  const unico = child(ambito.el, "rulebase");
  if (unico) out.push(unico);
  for (const tag of ["pre-rulebase", "post-rulebase"]) {
    const rb = child(ambito.el, tag);
    if (rb) out.push(rb);
  }
  return out;
}

/** Nombres de perfil directos de una regla, con las claves que usa el reporte. */
function perfilesDirectos(profileSetting) {
  const p = child(profileSetting, "profiles");
  if (!p) return {};
  const primero = (tag) => memberList(child(p, tag))[0];
  const salida = {
    profile_antivirus: primero("virus"),
    profile_anti_spyware: primero("spyware"),
    profile_vulnerability_protection: primero("vulnerability"),
    profile_url_filtering: primero("url-filtering"),
    profile_file_blocking: primero("file-blocking"),
    profile_wildfire_analysis: primero("wildfire-analysis"),
    profile_data_filtering: primero("data-filtering"),
  };
  return Object.fromEntries(Object.entries(salida).filter(([, v]) => v));
}

/** Reglas de descifrado de un ambito, con lo que usa la hoja Decryption. */
function reglasDescifrado(ambito) {
  return rulebasesDe(ambito).flatMap((rb) =>
    entradas(rb, "decryption/rules").map((e) => ({
      e,
      location: ambito.loc,
      name: entryName(e),
      action: texto(e, "action") || "no-decrypt",
      rule_type: child(e, "type")?.firstElementChild?.tagName || null,
      decryption_profile: texto(e, "profile") || null,
      disabled: texto(e, "disabled") === "yes",
    }))
  );
}

function evaluarDescifrado(bp, m) {
  const activaQueDescifra = (reglas) => reglas.some((r) => !r.disabled && r.action === "decrypt");
  const sharedDescifra = m.panorama && activaQueDescifra(reglasDescifrado(m.politicas[0]));
  const hayDeviceGroups = m.politicas.length > 1;

  for (const ambito of m.politicas) {
    const reglas = reglasDescifrado(ambito);
    for (const { e, disabled, ...configuration } of reglas) {
      const aplica = !disabled && configuration.action === "decrypt";
      agregar(bp, "policies", "decryption_rule", configuration, [
        w("B11", aplica ? Boolean(configuration.decryption_profile) : null,
          aplica && !configuration.decryption_profile ? "Regla decrypt sin Decryption profile." : ""),
      ]);
    }

    // En Panorama, cada device-group hereda las reglas de shared; shared solo se
    // evalua por separado cuando no hay device-groups.
    if (m.panorama && ambito.esShared && hayDeviceGroups) continue;
    const descifra = activaQueDescifra(reglas) || sharedDescifra;
    agregar(bp, "policies", "decryption_rulebase", { location: ambito.loc }, [
      w("B10", descifra, descifra ? "" : "No hay ninguna regla activa con acción decrypt."),
    ]);
  }
}

function evaluarReglas(bp, m) {
  let n = 0;
  for (const ambito of m.politicas) {
    for (const rb of rulebasesDe(ambito)) {
      for (const e of entradas(rb, "security/rules")) {
        n++;
        const accion = texto(e, "action") || "allow";
        const deshabilitada = texto(e, "disabled") === "yes";
        const campos = {
          application: memberList(child(e, "application")),
          service: memberList(child(e, "service")),
          source: memberList(child(e, "source")),
          destination: memberList(child(e, "destination")),
          from: memberList(child(e, "from")),
          to: memberList(child(e, "to")),
          source_user: memberList(child(e, "source-user")),
        };
        const ps = child(e, "profile-setting");
        const grupos = memberList(child(ps, "group"));
        const directos = perfilesDirectos(ps);
        const logSetting = texto(e, "log-setting");
        const logEnd = texto(e, "log-end") !== "no"; // por defecto PAN-OS registra al final
        const descripcion = texto(e, "description");
        const tags = memberList(child(e, "tag"));

        const configuration = {
          location: ambito.loc,
          name: entryName(e),
          action: accion,
          disabled: deshabilitada ? "yes" : "no",
          ...campos,
          log_setting: logSetting || null,
          log_end: logEnd,
          description: descripcion,
          tag: tags,
          ...(grupos.length ? { profile_setting: { group: grupos } } : {}),
          ...directos,
        };

        const allow = accion === "allow" && !deshabilitada;
        const soloAllow = (pasa) => (allow ? pasa : null);
        const anys = ["source", "destination", "application", "service"].filter((k) => esAny(campos[k]));

        const warnings = [
          w("A01", soloAllow(anys.length < 4), allow && anys.length === 4 ? "Origen, destino, aplicación y servicio en any." : ""),
          w("A02", soloAllow(!esAny(campos.application))),
          w("A03", soloAllow(!esAny(campos.service))),
          w("A04", soloAllow(grupos.length > 0 || Object.keys(directos).length > 0)),
          w("A05", soloAllow(logEnd)),
          w("A06", soloAllow(Boolean(logSetting))),
          w("A07", deshabilitada ? null : Boolean(descripcion)),
          w("A08", deshabilitada ? null : tags.length > 0),
        ];
        agregar(bp, "policies", "security_rule", configuration, warnings);
      }
    }

    // Reglas por defecto. En Panorama se sobrescriben en shared o en el
    // post-rulebase de un device-group; un DG sin override hereda de shared.
    const contenedorDefault = m.panorama ? child(ambito.el, "post-rulebase") : child(ambito.el, "rulebase");
    const defaults = entradas(contenedorDefault, "default-security-rules/rules");
    for (const nombre of ["intrazone-default", "interzone-default"]) {
      const regla = defaults.find((d) => entryName(d) === nombre);
      // Un device-group solo se evalua en las reglas que sobrescribe.
      if (m.panorama && !ambito.esShared && !regla) continue;
      const loguea = texto(regla, "log-end") === "yes";
      agregar(bp, "policies", "security_rulebase", { location: ambito.loc, name: nombre }, [
        w("A09", loguea, loguea ? "" : regla ? "log-end no habilitado." : "Sin override: por defecto no registra log."),
      ]);
    }
  }
  return n;
}

// ---------------------------------------------------------------------------
//  C. Perfiles de seguridad
// ---------------------------------------------------------------------------

/** Primera regla (en orden) que cubre una severidad; devuelve su accion. */
function accionParaSeveridad(reglas, severidad) {
  for (const r of reglas) {
    const sev = memberList(child(r, "severity"));
    const amenaza = texto(r, "threat-name") || "any";
    if (amenaza !== "any") continue;
    if (sev.includes(severidad) || sev.includes("any")) {
      const accion = child(r, "action");
      return accion?.firstElementChild?.tagName || "default";
    }
  }
  return null;
}

function severidadesSinBloqueo(perfil, severidades) {
  const reglas = entradas(perfil, "rules");
  return severidades
    .map((s) => [s, accionParaSeveridad(reglas, s)])
    .filter(([, a]) => !a || !ACCIONES_BLOQUEO.has(a))
    .map(([s, a]) => `${s}: ${a || "sin regla"}`);
}

function evaluarPerfiles(bp, m) {
  const cfg = (e, loc) => ({ name: entryName(e), location: loc });

  for (const { loc, el } of m.contenedoresPerfiles) {
    const profiles = child(el, "profiles");
    if (!profiles) continue;

    for (const e of entradas(profiles, "virus")) {
      // Solo se evaluan los decoders que conoce este check; un decoder ausente
      // en el XML queda con la accion por defecto, que no es reset-both.
      const decoders = new Map(entradas(e, "decoder").map((d) => [entryName(d), d]));
      const sinReset = (campo) =>
        DECODERS_AV.filter((d) => decoders.has(d))
          .map((d) => [d, texto(decoders.get(d), campo) || "default"])
          .filter(([, a]) => a !== "reset-both")
          .map(([d, a]) => `${d}: ${a}`);
      const malos = sinReset("action");
      const wf = sinReset("wildfire-action");
      const vacio = !decoders.size;
      agregar(bp, "objects", "antivirus_profile", cfg(e, loc), [
        w("C14", vacio ? false : malos.length === 0, vacio ? "El perfil no define decoders." : malos.join("; ")),
        w("C15", vacio ? false : wf.length === 0, vacio ? "El perfil no define decoders." : wf.join("; ")),
      ]);
    }

    for (const e of entradas(profiles, "spyware")) {
      const malos = severidadesSinBloqueo(e, ["critical", "high", "medium"]);
      const botnet = child(e, "botnet-domains");
      const listas = entradas(botnet, "lists").filter((x) => child(child(x, "action"), "sinkhole"));
      const categorias = entradas(botnet, "dns-security-categories").filter(
        (x) => /malware|command-and-control|cc/.test(entryName(x)) && texto(x, "action") === "sinkhole"
      );
      const sinkhole = listas.length > 0 || categorias.length > 0;
      agregar(bp, "objects", "anti_spyware_profile", cfg(e, loc), [
        w("C16", malos.length === 0, malos.join("; ")),
        w("C17", sinkhole, sinkhole ? "" : "Sin acción sinkhole en listas de dominios ni en categorías de DNS Security."),
      ]);
    }

    for (const e of entradas(profiles, "vulnerability")) {
      const malos = severidadesSinBloqueo(e, ["critical", "high"]);
      agregar(bp, "objects", "vulnerability_protection_profile", cfg(e, loc), [w("C18", malos.length === 0, malos.join("; "))]);
    }

    for (const e of entradas(profiles, "url-filtering")) {
      const bloqueadas = new Set(memberList(child(e, "block")));
      const faltan = URL_CATEGORIAS_BLOQUEO.filter((c) => !bloqueadas.has(c));
      const modo = child(ruta(e, "credential-enforcement"), "mode")?.firstElementChild?.tagName || "disabled";
      agregar(bp, "objects", "url_filtering_profile", cfg(e, loc), [
        w("C19", faltan.length === 0, faltan.length ? `No bloquea: ${faltan.join(", ")}.` : ""),
        w("C20", modo !== "disabled", modo === "disabled" ? "credential-enforcement deshabilitado." : ""),
      ]);
    }

    for (const e of entradas(profiles, "file-blocking")) {
      const bloqueados = new Set();
      for (const r of entradas(e, "rules")) {
        if (texto(r, "action") !== "block") continue;
        if (!esAny(memberList(child(r, "application")))) continue;
        for (const t of memberList(child(r, "file-type"))) bloqueados.add(t);
      }
      const faltan = bloqueados.has("any") ? [] : TIPOS_ARCHIVO_PELIGROSOS.filter((t) => !bloqueados.has(t));
      agregar(bp, "objects", "file_blocking_profile", cfg(e, loc), [
        w("C21", faltan.length === 0, faltan.length ? `No bloquea (para toda aplicación): ${faltan.join(", ")}.` : ""),
      ]);
    }

    for (const e of entradas(profiles, "decryption")) {
      const minima = texto(e, "ssl-protocol-settings/min-version") || "tls1-0"; // valor por defecto de PAN-OS
      const tlsOk = ["tls1-2", "tls1-3"].includes(minima);
      const proxy = child(e, "ssl-forward-proxy");
      const sinBloqueo = ["block-expired-certificate", "block-untrusted-issuer"].filter((t) => texto(proxy, t) !== "yes");
      agregar(bp, "objects", "decryption_profile", cfg(e, loc), [
        w("B12", tlsOk, tlsOk ? "" : `Versión mínima ${minima}.`),
        w("B13", sinBloqueo.length === 0, sinBloqueo.length ? `No activado: ${sinBloqueo.join(", ")}.` : ""),
      ]);
    }

    for (const e of entradas(profiles, "wildfire-analysis")) {
      const cubre = entradas(e, "rules").some(
        (r) =>
          esAny(memberList(child(r, "application"))) &&
          esAny(memberList(child(r, "file-type"))) &&
          ["both", ""].includes(texto(r, "direction"))
      );
      agregar(bp, "objects", "wildfire_analysis_profile", cfg(e, loc), [
        w("C22", cubre, cubre ? "" : "Ninguna regla cubre application any + file-type any en ambas direcciones."),
      ]);
    }
  }
}

// ---------------------------------------------------------------------------
//  D. Zonas y Zone Protection
// ---------------------------------------------------------------------------

function evaluarZonas(bp, m) {
  let n = 0;
  for (const eq of m.equipos) {
    if (!eq.dispositivo) continue;
    const perfilesZona = entradas(eq.dispositivo, "network/profiles/zone-protection-profile");

    for (const zp of perfilesZona) {
      const flood = ruta(zp, "flood");
      const faltan = ["tcp-syn", "udp", "icmp"].filter((t) => texto(flood, `${t}/enable`) !== "yes");
      agregar(bp, "objects", "zone_protection_profile", { name: entryName(zp), location: eq.loc }, [
        w("D25", faltan.length === 0, faltan.length ? `Flood protection deshabilitada para: ${faltan.join(", ")}.` : ""),
      ]);
    }

    for (const vsys of entradas(eq.dispositivo, "vsys")) {
      for (const z of entradas(vsys, "zone")) {
        n++;
        const red = child(z, "network");
        const tipo = red?.firstElementChild?.tagName || "";
        const zpNombre = texto(red, "zone-protection-profile");
        const pbpTexto = texto(red, "enable-packet-buffer-protection");
        const aplica = tipo !== "tap" && tipo !== "";
        agregar(
          bp, "network", "zone",
          {
            name: entryName(z),
            location: m.panorama ? `${eq.loc} / ${entryName(vsys)}` : entryName(vsys),
            ...(eq.plantilla ? { template_name: eq.loc } : {}),
            type: tipo,
            zone_protection_profile: zpNombre || null,
            packet_buffer_protection_enabled: pbpTexto === "yes",
            user_id_enabled: texto(z, "enable-user-identification") === "yes",
          },
          [
            w("D23", aplica ? Boolean(zpNombre) : null, aplica ? "" : `Zona ${tipo || "sin tipo"}: no aplica.`),
            w(
              "D24",
              !aplica ? null : pbpTexto === "yes" ? true : pbpTexto === "no" ? false : null,
              aplica && !pbpTexto ? "No está explícito en la configuración: depende del valor por defecto de tu versión de PAN-OS; verifícalo." : ""
            ),
          ]
        );
      }
    }
  }
  return n;
}

// ---------------------------------------------------------------------------
//  E / F. Administracion y actualizaciones dinamicas
// ---------------------------------------------------------------------------

/** En un template, lo ausente no se evalua: el firewall puede tenerlo local. */
function enPlantilla(eq, presente, pasa, mensaje) {
  if (eq.plantilla && !presente) return [null, "No definido en el template (puede estar configurado en el firewall)."];
  return [pasa, mensaje];
}

function rolDe(usuario) {
  const rb = ruta(usuario, "permissions/role-based");
  const primero = rb?.firstElementChild;
  if (!primero) return null;
  if (primero.tagName === "custom") return texto(primero, "profile") || "custom";
  return primero.tagName;
}

function evaluarAdministracion(bp, m) {
  for (const eq of m.equipos) {
    const sistema = ruta(eq.dispositivo, "deviceconfig/system");
    const gestion = ruta(eq.dispositivo, "deviceconfig/setting/management");
    const mgt = child(eq.config, "mgt-config");
    const ha = ruta(eq.dispositivo, "deviceconfig/high-availability");
    // Logs de sistema/config: Panorama los define en <panorama>; firewall y templates, en shared.
    const logSettings = (!eq.plantilla && m.panorama && ruta(eq.config, "panorama/log-settings")) || ruta(eq.config, "shared/log-settings");
    if (eq.plantilla && !sistema && !gestion && !mgt && !ha && !logSettings) continue;

    // --- setup ---
    const servicio = child(sistema, "service");
    const telnet = texto(servicio, "disable-telnet");
    const http = texto(servicio, "disable-http");
    // Perfiles de gestion de interfaces con telnet/http habilitados.
    const perfilesInseguros = entradas(eq.dispositivo, "network/profiles/interface-management-profile")
      .filter((p) => texto(p, "telnet") === "yes" || texto(p, "http") === "yes")
      .map(entryName);
    const inseguro = [];
    if (telnet === "no") inseguro.push("Telnet habilitado en la gestión");
    if (http === "no") inseguro.push("HTTP habilitado en la gestión");
    if (perfilesInseguros.length) inseguro.push(`perfiles de interfaz con Telnet/HTTP: ${perfilesInseguros.join(", ")}`);
    const e26 = enPlantilla(eq, Boolean(servicio) || perfilesInseguros.length > 0, inseguro.length === 0, inseguro.join("; "));

    const permitidas = entradas(sistema, "permitted-ip");
    const e27 = enPlantilla(eq, permitidas.length > 0, permitidas.length > 0, permitidas.length ? "" : "Sin permitted-ip: la gestión acepta cualquier origen.");

    const idleTxt = texto(gestion, "idle-timeout");
    const idle = idleTxt ? Number(idleTxt) : 60; // valor por defecto de PAN-OS
    const e32 = enPlantilla(
      eq, Boolean(idleTxt), idle > 0 && idle <= UMBRALES.idleTimeoutMax,
      idle > UMBRALES.idleTimeoutMax || idle === 0 ? `idle-timeout ${idleTxt ? idle : "por defecto (60)"} min.` : ""
    );

    const ntp1 = texto(sistema, "ntp-servers/primary-ntp-server/ntp-server-address");
    const ntp2 = texto(sistema, "ntp-servers/secondary-ntp-server/ntp-server-address");
    const e35 = enPlantilla(eq, Boolean(ntp1 || ntp2), Boolean(ntp1 || ntp2), ntp1 || ntp2 ? (ntp1 && ntp2 ? "" : "Solo un servidor NTP; se recomiendan dos.") : "Sin servidores NTP.");

    const intentos = Number(texto(gestion, "admin-lockout/failed-attempts") || 0);
    const e33 = enPlantilla(eq, Boolean(ruta(gestion, "admin-lockout")), intentos > 0,
      intentos > 0 ? "" : "admin-lockout sin intentos fallidos configurados.");

    const banner = texto(sistema, "login-banner");
    const e34 = enPlantilla(eq, Boolean(banner), Boolean(banner), banner ? "" : "Sin login-banner.");

    // SNMP: sin configuracion no aplica; v2c es la falla.
    const snmpVersion = ruta(sistema, "snmp-setting/access-setting/version")?.firstElementChild?.tagName || null;
    const e36 = snmpVersion ? [snmpVersion === "v3", snmpVersion === "v3" ? "" : `SNMP ${snmpVersion}.`] : [null, "SNMP no configurado."];

    // Reenvio de logs: basta un match-list con algun destino en system y en config.
    const conDestino = (tipo) =>
      entradas(child(logSettings, tipo), "match-list").some((e) =>
        [...e.children].some((c) => /^send-/.test(c.tagName) && (c.children.length > 0 || textOf(c) === "yes"))
      );
    const sinReenvio = ["system", "config"].filter((t) => !conDestino(t));
    const e37 = enPlantilla(eq, Boolean(logSettings), sinReenvio.length === 0,
      sinReenvio.length ? `Sin reenvío de logs de: ${sinReenvio.join(", ")}.` : "");

    agregar(bp, "device", "setup", { name: texto(sistema, "hostname") || eq.loc, location: eq.loc }, [
      w("E26", ...e26), w("E27", ...e27), w("E32", ...e32), w("E33", ...e33), w("E34", ...e34),
      w("E35", ...e35), w("E36", ...e36), w("E37", ...e37),
    ]);

    // --- alta disponibilidad ---
    // PAN-OS guarda el grupo directo en <group> o, en versiones antiguas, en <group><entry>.
    const grupoHa = children(child(ha, "group"), "entry")[0] || child(ha, "group");
    const haActiva = texto(ha, "enabled") === "yes";
    if (ha || !eq.plantilla) {
      const modo = ruta(grupoHa, "mode")?.firstElementChild?.tagName || null;
      const monitoreo = ruta(grupoHa, "monitoring") || ruta(ha, "group/monitoring");
      const linkOk = texto(monitoreo, "link-monitoring/enabled") !== "no" && entradas(monitoreo, "link-monitoring/link-group").length > 0;
      const pathOk = texto(monitoreo, "path-monitoring/enabled") !== "no" && entradas(monitoreo, "path-monitoring/path-group/virtual-router").length +
        entradas(monitoreo, "path-monitoring/path-group/virtual-wire").length + entradas(monitoreo, "path-monitoring/path-group/vlan").length +
        entradas(monitoreo, "path-monitoring/path-group/logical-router").length > 0;
      const syncTxt = texto(grupoHa, "configuration-synchronization/enabled");
      const syncOk = syncTxt !== "no"; // por defecto PAN-OS sincroniza
      agregar(bp, "device", "high_availability", {
        location: eq.loc,
        enabled: haActiva ? "yes" : "no",
        group: {
          ...(modo ? { mode: { [modo]: {} } } : {}),
          configuration_synchronization: { enabled: syncOk ? "yes" : "no" },
        },
      }, [
        w("G41", haActiva, haActiva ? "" : "HA deshabilitado (puede ser intencional en un equipo standalone)."),
        w("G42", haActiva ? linkOk : null, !haActiva ? "" : !linkOk ? "Sin link groups monitoreados." : pathOk ? "" : "Sin path monitoring."),
        w("G43", haActiva ? syncOk : null, haActiva && !syncOk ? "configuration-synchronization deshabilitado." : ""),
      ]);
    }

    // --- administradores ---
    if (mgt || !eq.plantilla) {
      const usuarios = entradas(mgt, "users");
      const admins = usuarios.map((u) => ({
        name: entryName(u),
        role: rolDe(u),
        authentication_profile: texto(u, "authentication-profile") || null,
        password_profile: texto(u, "password-profile") || null,
        local: Boolean(child(u, "phash")),
      }));
      const complejidad = ruta(mgt, "password-complexity");
      const habilitada = texto(complejidad, "enabled") === "yes";
      const minimo = Number(texto(complejidad, "minimum-length") || 0);
      const e28 = enPlantilla(eq, Boolean(complejidad), habilitada && minimo >= UMBRALES.passwordMinimo,
        !habilitada ? "password-complexity no habilitado." : minimo < UMBRALES.passwordMinimo ? `Longitud mínima ${minimo || "sin definir"}.` : "");
      const localesSinPerfil = admins.filter((a) => a.local && !a.password_profile).map((a) => a.name);
      const e29 = enPlantilla(eq, usuarios.length > 0, habilitada || localesSinPerfil.length === 0,
        !habilitada && localesSinPerfil.length ? `Sin password profile: ${localesSinPerfil.join(", ")}.` : "");
      const hayAdmin = admins.some((a) => a.name === "admin");
      const e30 = enPlantilla(eq, usuarios.length > 0, !hayAdmin, hayAdmin ? "La cuenta admin existe." : "");
      const superSinAuth = admins.filter((a) => a.role === "superuser" && !a.authentication_profile).map((a) => a.name);
      const hayLocales = admins.some((a) => a.role === "superuser");
      const e31 = enPlantilla(eq, usuarios.length > 0, hayLocales ? superSinAuth.length === 0 : null,
        superSinAuth.length ? `Sin authentication profile: ${superSinAuth.join(", ")}.` : "");

      agregar(bp, "device", "administrator", { location: eq.loc, admins: admins.map(({ local, ...a }) => a) }, [
        w("E28", ...e28), w("E29", ...e29), w("E30", ...e30), w("E31", ...e31),
      ]);
    }

    // --- actualizaciones dinamicas ---
    const programa = child(sistema, "update-schedule");
    const leer = (tag) => {
      const rec = ruta(programa, `${tag}/recurring`);
      const frecuencia = rec?.firstElementChild;
      if (!frecuencia) return null;
      return { recurring: { [frecuencia.tagName]: { action: texto(frecuencia, "action") || null, at: texto(frecuencia, "at") || null } } };
    };
    const av = leer("anti-virus");
    const amenazas = leer("threats");
    const wildfire = leer("wildfire");
    const accion = (x) => (x ? Object.values(x.recurring)[0].action : null);
    const frecuenciaWf = wildfire ? Object.keys(wildfire.recurring)[0] : null;

    const f38 = enPlantilla(eq, Boolean(av), accion(av) === "download-and-install", av ? (accion(av) === "download-and-install" ? "" : `Acción: ${accion(av) || "sin definir"}.`) : "Sin programación.");
    const f39 = enPlantilla(eq, Boolean(amenazas), accion(amenazas) === "download-and-install", amenazas ? (accion(amenazas) === "download-and-install" ? "" : `Acción: ${accion(amenazas) || "sin definir"}.`) : "Sin programación.");
    const wfOk = ["real-time", "every-min"].includes(frecuenciaWf) && (frecuenciaWf === "real-time" || accion(wildfire) === "download-and-install");
    const f40 = enPlantilla(eq, Boolean(wildfire), wfOk, wildfire ? (wfOk ? "" : `Frecuencia ${frecuenciaWf}, acción ${accion(wildfire) || "sin definir"}.`) : "Sin programación.");

    agregar(bp, "device", "dynamic_updates", { location: eq.loc, anti_virus: av, threats: amenazas, wildfire }, [
      w("F38", ...f38), w("F39", ...f39), w("F40", ...f40),
    ]);
  }
}

// ---------------------------------------------------------------------------
//  H. Certificados
// ---------------------------------------------------------------------------

const MESES = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

function fechaCertificado(e) {
  const epoch = Number(texto(e, "expiry-epoch"));
  if (epoch > 0) return new Date(epoch * 1000);
  const m = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})/.exec(texto(e, "not-valid-after"));
  if (!m || !(m[1].toLowerCase() in MESES)) return null;
  return new Date(Date.UTC(Number(m[6]), MESES[m[1].toLowerCase()], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])));
}

/** Ubicacion legible de un certificado a partir de sus ancestros. */
function ubicacionCertificado(contenedor, m) {
  // Se sube hasta la raiz: dentro de un template hay otro <config> anidado,
  // asi que no se puede cortar en el primer <config>.
  const partes = [];
  let ambito = null;
  for (let el = contenedor.parentElement; el; el = el.parentElement) {
    const padre = el.parentElement?.tagName;
    if (el.tagName === "entry" && (padre === "template" || padre === "template-stack")) partes.unshift(entryName(el));
    if (el.tagName === "entry" && padre === "vsys" && !ambito) ambito = entryName(el);
    if (el.tagName === "shared" && !ambito) ambito = "shared";
    if (el.tagName === "panorama" && !ambito) ambito = "Panorama";
  }
  if (ambito) partes.push(ambito);
  return partes.join(" / ") || (m.panorama ? "Panorama" : "shared");
}

function evaluarCertificados(bp, m, config, ahora) {
  let n = 0;
  for (const cont of config.getElementsByTagName("certificate")) {
    for (const e of children(cont, "entry")) {
      if (!child(e, "not-valid-after") && !child(e, "expiry-epoch")) continue;
      n++;
      const fecha = fechaCertificado(e);
      const dias = fecha ? Math.floor((fecha - ahora) / 86400000) : null;
      const vencido = dias !== null && dias < 0;
      agregar(bp, "device", "certificate", {
        name: entryName(e),
        location: ubicacionCertificado(cont, m),
        expiry: texto(e, "not-valid-after") || (fecha ? fecha.toUTCString() : null),
        common_name: texto(e, "common-name") || null,
      }, [
        w("H44", dias === null ? null : !vencido, dias === null ? "No se pudo leer la fecha de vencimiento." : vencido ? `Venció hace ${-dias} día(s).` : ""),
        w("H45", dias === null || vencido ? null : dias > UMBRALES.diasCertificado, !vencido && dias !== null && dias <= UMBRALES.diasCertificado ? `Vence en ${dias} día(s).` : ""),
      ]);
    }
  }
  return n;
}

// ---------------------------------------------------------------------------
//  Punto de entrada
// ---------------------------------------------------------------------------

/**
 * @param {Element} config  elemento <config> del running-config
 * @param {object}  [opciones]
 * @param {Date}    [opciones.ahora]
 * @param {(mensaje: string, nivel?: string) => void} [log]
 * @returns {object} reporte con {information, best_practices}
 */
export function evaluarConfigLocal(config, { ahora = new Date() } = {}, log = () => {}) {
  if (!config || config.tagName !== "config") throw new Error("La configuracion no tiene un elemento <config>.");
  const m = modelo(config);
  const bp = {};

  const reglas = evaluarReglas(bp, m);
  evaluarDescifrado(bp, m);
  evaluarPerfiles(bp, m);
  const zonas = evaluarZonas(bp, m);
  evaluarAdministracion(bp, m);
  const certificados = evaluarCertificados(bp, m, config, ahora);

  const plantillas = m.equipos.filter((e) => e.plantilla).length;
  log(
    `Evaluacion local: ${m.panorama ? `Panorama con ${m.politicas.length - 1} device-group(s) y ${plantillas} template(s)` : "firewall"}, ` +
      `${reglas} regla(s), ${zonas} zona(s), ${certificados} certificado(s).`
  );

  const sistema = ruta(m.dispositivo, "deviceconfig/system");
  return {
    information: {
      platform: m.panorama ? "panorama" : "ngfw",
      PanOS_version: config.getAttribute("version") || "",
      device_ip_address: texto(sistema, "ip-address"),
      hostname: texto(sistema, "hostname"),
      vsys: m.panorama ? [] : m.politicas.map((p) => p.loc),
      last_updated_time: selloLocal(ahora),
      bpa_version: "PAN Helper local",
      origen: "local",
      checks_locales: Object.keys(CHECKS_LOCALES).length,
    },
    best_practices: bp,
  };
}

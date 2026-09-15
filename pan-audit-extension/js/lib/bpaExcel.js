// js/lib/bpaExcel.js
// Excel del Best Practice Assessment. Port de build() y las hojas _hoja_*()
// de la skill bpa-netdata (scripts/bpa.py), con marca neutral PAN Helper y
// escrito con js/lib/xlsxWriter.js (sin librerias).
//
// Hojas: Resumen, Hallazgos, Adopcion seguridad, Reglas, BP Mode (con radar),
// Decryption, Certificados, Zonas, Perfiles, Plataforma y Detalle (base de
// los COUNTIFS). Las formulas llevan su valor precalculado, asi el archivo se
// ve igual aunque la aplicacion no recalcule al abrir.
//
// "adoption" / "adoption_summary" no siempre vienen en la respuesta de SCM.
// Cuando faltan, Reglas / Adopcion / BP Mode se reconstruyen desde
// best_practices.policies.security_rule (mismo criterio que la skill). Las
// reglas con Security Profile Group solo se resuelven si se aporta el
// running-config.xml (ver parsearGruposPerfiles).
//
// Modulo puro salvo parsearGruposPerfiles(), que recibe un Document ya
// parseado (DOMParser en el navegador).

import { Libro, letraColumna } from "./xlsxWriter.js";
import { cargarChecks, esPanorama, checksEnFalla, SEVERIDADES } from "./bpaReport.js";

// ---------------------------------------------------------------------------
//  Paleta (neutral PAN Helper) y estilos base
// ---------------------------------------------------------------------------

const NAVY = "123A63";
const ACCENT = "1A5FB4";
const WHITE = "FFFFFF";
const GREY_H = "EAEFF7";
const ZEBRA = "F4F6FA";
const BORDE = "D5DCE6";

const SEV_FILL = { "Crítico": "FBE3E3", "Advertencia": "FCEFDD", "Informativo": "EAEFF7" };
const SEV_TXT = { "Crítico": "C00000", "Advertencia": "B26A00", "Informativo": "335A8A" };
const OK_TXT = "1E7A32";
const BAD_TXT = "C00000";
const WARN_TXT = "B26A00";
const NA_TXT = "667085";
const NA_FILL = "EEF1F5";

const SEVORDEN = { "Crítico": 0, "Advertencia": 1, "Informativo": 2 };

const FMT_PCT_LITERAL = "0.0\\%";   // el valor ya es 0-100
const FMT_PCT = "0.0%";             // el valor es 0-1
const FMT_ENTERO = "#,##0";

/** Fuente: (tamano, negrita, color) como f() de la skill. */
const f = (tam = 10, negrita = false, color = "000000") => ({ tam, negrita, color });

const zebra = (fila) => (fila % 2 === 0 ? ZEBRA : WHITE);

/** round(x, 1) de Python para los porcentajes. */
const r1 = (x) => Math.round(x * 10) / 10;

const unir = (lista) => [...new Set(lista)].sort().join("; ");

function estiloEncabezado(h = "left", extra = {}) {
  return { fuente: f(10, true, WHITE), relleno: NAVY, h, v: "center", ajustar: true, borde: BORDE, ...extra };
}

/** Titulo (fila 1), subtitulo (fila 2) y encabezados (fila 3); datos desde la fila 4. */
function hojaBase(libro, nombre, titulo, subtitulo, encabezados, colsIzq = [1]) {
  const ws = libro.hoja(nombre).sinCuadricula();
  const n = encabezados.length;
  ws.combinar(1, 1, 1, n).celda(1, 1, titulo, { fuente: f(14, true, WHITE), relleno: NAVY, h: "left", v: "center", sangria: 1 });
  ws.alto(1, 28);
  ws.combinar(2, 1, 2, n).celda(2, 1, subtitulo, { fuente: f(9, false, WHITE), relleno: ACCENT, h: "left", v: "center", sangria: 1 });
  encabezados.forEach((h, j) => {
    ws.celda(3, j + 1, h, {
      fuente: f(9, true, WHITE), relleno: NAVY, borde: BORDE, v: "center", ajustar: true,
      h: colsIzq.includes(j + 1) ? "left" : "center",
    });
  });
  ws.alto(3, 24).congelar("A4");
  return ws;
}

function avisoSiVacio(ws, fila, n, mensaje = "Sin datos en este reporte.") {
  if (fila > 4) return;
  ws.combinar(4, 1, 4, n).celda(4, 1, mensaje, { fuente: f(9, false, NA_TXT), h: "left", v: "center", sangria: 1, borde: BORDE });
}

function anchos(ws, lista) {
  lista.forEach((w, i) => ws.ancho(i + 1, w));
}

function filtroDesde(ws, filaEnc, nCols) {
  ws.filtro(`A${filaEnc}:${letraColumna(nCols)}${Math.max(ws.maxFila, filaEnc)}`);
}

/** Celda de dato con zebra y borde. */
function dato(ws, fila, col, valor, { fuente = f(9), h = "left", v = "center", ajustar = false, relleno, formato } = {}) {
  ws.celda(fila, col, valor, { fuente, relleno: relleno || zebra(fila), borde: BORDE, h, v, ajustar, formato });
}

// ---------------------------------------------------------------------------
//  Security Profile Groups desde el running-config.xml
// ---------------------------------------------------------------------------

const CATEGORIA_TAG_GRUPO = {
  virus: "antivirus_profile_enabled",
  spyware: "anti_spyware_profile_enabled",
  vulnerability: "vulnerability_protection_profile_enabled",
  "url-filtering": "url_filtering_profile_enabled",
  "file-blocking": "file_blocking_profile_enabled",
  "wildfire-analysis": "wildfire_analysis_profile_enabled",
  "data-filtering": "data_filtering_profile_enabled",
};

/**
 * {nombre_grupo: {categoria: perfil}} de todos los <profile-group> del XML,
 * en cualquier nivel (shared, vsys, device-group, template). Si el mismo
 * nombre aparece en varios lugares, se conserva la primera definicion.
 * @param {Document|Element} doc
 */
export function parsearGruposPerfiles(doc) {
  const hijos = (el, tag) => [...el.children].filter((c) => c.tagName === tag);
  const grupos = {};
  for (const pg of doc.getElementsByTagName("profile-group")) {
    for (const entry of hijos(pg, "entry")) {
      const nombre = entry.getAttribute("name");
      if (!nombre) continue;
      const cats = {};
      for (const [tag, cat] of Object.entries(CATEGORIA_TAG_GRUPO)) {
        const el = hijos(entry, tag)[0];
        if (!el) continue;
        const miembros = hijos(el, "member").map((m) => m.textContent).filter(Boolean);
        if (miembros.length) cats[cat] = miembros[0];
      }
      if (Object.keys(cats).length && !(nombre in grupos)) grupos[nombre] = cats;
    }
  }
  return grupos;
}

// ---------------------------------------------------------------------------
//  Reconstruccion sin adoption / adoption_summary
// ---------------------------------------------------------------------------

const reglasSeguridad = (data) => {
  const r = data?.best_practices?.policies?.security_rule;
  return Array.isArray(r) ? r : [];
};

const esObjeto = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Un campo "con valor": no vacio. Los textos "no"/"false" cuentan como falso. */
function conValor(v) {
  if (v === null || v === undefined) return false;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s !== "" && s !== "no" && s !== "false";
  }
  if (Array.isArray(v)) return v.length > 0;
  return Boolean(v);
}

function noEsAny(v) {
  if (v === null || v === undefined) return false;
  if (Array.isArray(v)) return v.length > 0 && !(v.length === 1 && v[0] === "any");
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s !== "" && s !== "any";
  }
  return false;
}

const esAny = (v) => (Array.isArray(v) ? v.length === 1 && v[0] === "any" : v === "any");

function perfilCumpleMap(data) {
  const objs = data?.best_practices?.objects || {};
  const TIPOS = {
    antivirus_profile: "antivirus_profile_enabled",
    anti_spyware_profile: "anti_spyware_profile_enabled",
    vulnerability_protection_profile: "vulnerability_protection_profile_enabled",
    url_filtering_profile: "url_filtering_profile_enabled",
    file_blocking_profile: "file_blocking_profile_enabled",
    wildfire_analysis_profile: "wildfire_analysis_profile_enabled",
    dns_security_profile: "dns_security_enabled",
  };
  const mapa = {};
  for (const [clave, cat] of Object.entries(TIPOS)) {
    const d = {};
    for (const it of objs[clave] || []) {
      const nombre = it?.configuration?.name;
      if (nombre) d[String(nombre)] = checksEnFalla(it).length === 0;
    }
    mapa[cat] = d;
  }
  return mapa;
}

function capacidadesRegla(c, grupoCategorias = null) {
  const cat = (clave, ...campos) =>
    grupoCategorias ? clave in grupoCategorias : campos.some((campo) => conValor(c[campo]));

  return {
    app_id_enabled: noEsAny(c.application ?? c.applications),
    user_id_enabled: noEsAny(c.source_user),
    service_port_configured: noEsAny(c.service),
    log_forwarding_enabled: conValor(c.log_setting),
    antivirus_profile_enabled: cat("antivirus_profile_enabled", "profile_antivirus"),
    anti_spyware_profile_enabled: cat("anti_spyware_profile_enabled", "profile_anti_spyware"),
    vulnerability_protection_profile_enabled: cat("vulnerability_protection_profile_enabled", "profile_vulnerability_protection"),
    url_filtering_profile_enabled: cat("url_filtering_profile_enabled", "profile_url_filtering"),
    file_blocking_profile_enabled: cat("file_blocking_profile_enabled", "profile_file_blocking"),
    wildfire_analysis_profile_enabled: cat(
      "wildfire_analysis_profile_enabled", "profile_wildfire_analysis", "profile_virus_and_wildfire_analysis"
    ),
    dns_security_enabled: cat("dns_security_enabled", "profile_dns_security"),
    // Vive dentro del perfil de URL Filtering, no en la regla: no se adivina.
    credential_theft_enabled: null,
    log_end: c.log_end === null || c.log_end === undefined ? null : conValor(c.log_end),
  };
}

const CAP_KEYS = [
  "app_id_enabled", "user_id_enabled", "log_forwarding_enabled",
  "antivirus_profile_enabled", "anti_spyware_profile_enabled",
  "vulnerability_protection_profile_enabled", "url_filtering_profile_enabled",
  "file_blocking_profile_enabled", "wildfire_analysis_profile_enabled",
  "dns_security_enabled", "credential_theft_enabled",
];

/** Primer grupo de la regla (profile_setting.group), o null. */
function grupoDeRegla(c) {
  const g = c?.profile_setting?.group;
  if (Array.isArray(g)) return g.length ? String(g[0]) : null;
  return g ? String(g) : null;
}

/**
 * Reglas, adopcion por ubicacion y promedios globales desde best_practices.
 * @returns {{filas, porUbicacion, promedios, total}}
 */
export function reglasFallback(data, grupos = null) {
  const AMP = [["application", "App"], ["service", "Svc"], ["from", "SrcZona"], ["source", "SrcAddr"], ["destination", "DstAddr"]];
  const filas = [];
  const porUbi = new Map();
  const sumaGlobal = {};
  let total = 0;

  for (const e of reglasSeguridad(data)) {
    if (!esObjeto(e)) continue;
    const c = e.configuration || {};
    const grupo = grupoDeRegla(c);
    const caps = capacidadesRegla(c, grupo && grupos ? grupos[grupo] || null : null);

    let faltan = 0;
    const capsTxt = CAP_KEYS.map((k) => {
      const v = caps[k];
      if (v === null) return "—";
      if (v) return "Sí";
      faltan++;
      return "No";
    });

    const anys = AMP.filter(([campo]) => esAny(c[campo])).map(([, l]) => l);
    const loc = c.location || c.container || "—";

    filas.push({
      dg: String(loc),
      regla: String(c.rule_name || c.name || "—"),
      accion: String(c.action || "—"),
      hab: String(c.disabled ?? "no").trim().toLowerCase() === "yes" || c.disabled === true ? "No" : "Sí",
      faltan,
      caps: capsTxt,
      nany: anys.length,
      amp: anys.length ? anys.join(", ") : "—",
      serial: "—", // sale de 'targets', que solo existe en adoption
      desc: String(c.description || "").trim() ? "Sí" : "No",
    });

    if (!porUbi.has(loc)) porUbi.set(loc, { n: 0, suma: {} });
    const b = porUbi.get(loc);
    for (const k of [...CAP_KEYS, "service_port_configured", "log_end"]) {
      const v = caps[k];
      if (v === null) continue;
      b.suma[k] = (b.suma[k] || 0) + (v ? 1 : 0);
      sumaGlobal[k] = (sumaGlobal[k] || 0) + (v ? 1 : 0);
    }
    b.n++;
    total++;
  }

  const porUbicacion = [...porUbi.entries()]
    .map(([loc, b]) => {
      const m = { total_rule_count: b.n };
      for (const [k, s] of Object.entries(b.suma)) m[k] = r1((100 * s) / b.n);
      return [String(loc), m];
    })
    .sort((a, b) => b[1].total_rule_count - a[1].total_rule_count || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const promedios = {};
  if (total) for (const [k, s] of Object.entries(sumaGlobal)) promedios[k] = r1((100 * s) / total);

  return { filas, porUbicacion, promedios, total };
}

/**
 * 'En BP Mode' reconstruido: reglas cuyo perfil asignado cumple sus propios
 * checks, sobre el TOTAL de reglas (mismo denominador que 'Habilitado', asi
 * BP Mode nunca lo supera).
 * @returns {{porcentajes: object, gruposSinResolver: number}}
 */
export function bpModeFallback(data, grupos = null, totalReglas = 0) {
  const reglas = reglasSeguridad(data);
  if (!reglas.length) return { porcentajes: {}, gruposSinResolver: 0 };

  const cumpleMap = perfilCumpleMap(data);
  const CAMPO_A_CAT = [
    ["profile_antivirus", "antivirus_profile_enabled"],
    ["profile_anti_spyware", "anti_spyware_profile_enabled"],
    ["profile_vulnerability_protection", "vulnerability_protection_profile_enabled"],
    ["profile_url_filtering", "url_filtering_profile_enabled"],
    ["profile_file_blocking", "file_blocking_profile_enabled"],
    ["profile_wildfire_analysis", "wildfire_analysis_profile_enabled"],
    ["profile_virus_and_wildfire_analysis", "wildfire_analysis_profile_enabled"],
    ["profile_dns_security", "dns_security_enabled"],
  ];

  const cumpleN = {};
  const vistas = new Set();
  let gruposSinResolver = 0;
  let vistasReglas = 0;

  const contar = (cat, nombre) => {
    if (!nombre) return;
    vistas.add(cat);
    if (cumpleMap[cat]?.[String(nombre)] === true) cumpleN[cat] = (cumpleN[cat] || 0) + 1;
  };

  for (const e of reglas) {
    if (!esObjeto(e)) continue;
    vistasReglas++;
    const c = e.configuration || {};
    const grupo = grupoDeRegla(c);
    if (grupo) {
      // Con grupo, los campos directos de la regla no son confiables (se
      // verifico en un caso real que quedan fijos): solo vale el XML.
      const def = grupos ? grupos[grupo] : null;
      if (!def) {
        gruposSinResolver++;
        continue;
      }
      for (const [cat, nombre] of Object.entries(def)) contar(cat, nombre);
    } else {
      for (const [campo, cat] of CAMPO_A_CAT) contar(cat, c[campo]);
    }
  }

  const denom = totalReglas || vistasReglas;
  const porcentajes = {};
  if (denom) for (const cat of vistas) porcentajes[cat] = r1((100 * (cumpleN[cat] || 0)) / denom);
  return { porcentajes, gruposSinResolver };
}

// ---------------------------------------------------------------------------
//  Hojas
// ---------------------------------------------------------------------------

function metricasPonderadas(filasSummary, { excluirBpMode }) {
  let total = 0;
  const acc = {};
  for (const e of filasSummary) {
    if (!esObjeto(e)) continue;
    const m = e.metrics || {};
    const n = m.total_rule_count;
    if (typeof n !== "number" || n <= 0) continue;
    total += n;
    for (const [k, v] of Object.entries(m)) {
      if (typeof v !== "number") continue;
      if (excluirBpMode && k.endsWith("_bp_mode")) continue;
      acc[k] = (acc[k] || 0) + v * n;
    }
  }
  return { total, acc };
}

function hojaResumen(libro, ctx) {
  const { data, cliente, filas, fb } = ctx;
  const info = data.information || {};
  const ws = libro.hoja("Resumen").sinCuadricula();
  anchos(ws, [22, 16, 16, 16, 16, 16]);

  ws.combinar(1, 1, 1, 6).celda(1, 1, `Reporte BPA — ${cliente}`, { fuente: f(20, true, WHITE), relleno: NAVY, h: "left", v: "center", sangria: 1 });
  ws.alto(1, 40);
  const subtitulo = ctx.local
    ? "Evaluación local de PAN Helper · checks propios sobre la configuración · no es el BPA oficial de Palo Alto"
    : "Best Practice Assessment · Strata Cloud Manager · PAN Helper";
  ws.combinar(2, 1, 2, 6).celda(2, 1, subtitulo, {
    fuente: f(10, false, WHITE), relleno: ACCENT, h: "left", v: "center", sangria: 1,
  });
  ws.alto(2, 20);

  let r = 4;
  ws.celda(r++, 1, "Información del dispositivo", { fuente: f(12, true, NAVY) });
  const vsys = Array.isArray(info.vsys) ? info.vsys.join(", ") : String(info.vsys ?? "");
  const pares = [
    ["Cliente", cliente],
    ["Tipo", ctx.panorama ? "Panorama" : "Firewall (standalone)"],
    ["Plataforma", String(info.platform ?? "").toUpperCase()],
    ["Versión PAN-OS", String(info.PanOS_version ?? "")],
    ["Versión BPA", String(info.bpa_version ?? "")],
    ["IP del dispositivo", String(info.device_ip_address ?? "")],
    ["VSYS", vsys],
    ["Fecha del análisis", String(info.last_updated_time ?? "").slice(0, 19)],
  ];
  for (const [k, v] of pares) {
    ws.celda(r, 1, k, { fuente: f(10, true), relleno: GREY_H, borde: BORDE });
    ws.celda(r, 2, v, { fuente: f(10), borde: BORDE }).estilo(r, 3, { borde: BORDE }).combinar(r, 2, r, 3);
    r++;
  }

  // KPIs con formulas sobre la hoja Detalle.
  r++;
  ws.celda(r++, 1, "Resumen de cumplimiento", { fuente: f(12, true, NAVY) });
  const kr = r;
  const { R_EST, R_EXC } = ctx.rangos;
  const noExcl = filas.filter((x) => !x.excluido);
  const cuenta = (estado, lista = noExcl) => lista.filter((x) => x.estado === estado).length;
  const cumple = cuenta("Cumple");
  const falla = cuenta("Falla");

  const kpis = [
    ["Aplicables", `COUNTIFS(${R_EST},"Cumple",${R_EXC},"No")+COUNTIFS(${R_EST},"Falla",${R_EXC},"No")`, cumple + falla, ACCENT],
    ["Cumple", `COUNTIFS(${R_EST},"Cumple",${R_EXC},"No")`, cumple, OK_TXT],
    ["Falla", `COUNTIFS(${R_EST},"Falla",${R_EXC},"No")`, falla, BAD_TXT],
    ["% Cumplimiento", `IFERROR(B${kr + 1}/A${kr + 1},0)`, cumple + falla ? cumple / (cumple + falla) : 0, ACCENT],
    ["No aplica", `COUNTIFS(${R_EST},"No aplica",${R_EXC},"No")`, cuenta("No aplica"), NA_TXT],
    ["Excluidos", `COUNTIF(${R_EXC},"Sí")`, filas.length - noExcl.length, NA_TXT],
  ];
  kpis.forEach(([lbl, formula, valor, color], i) => {
    ws.celda(kr, i + 1, lbl, { fuente: f(9, true, WHITE), relleno: NAVY, h: "center", borde: BORDE });
    ws.celda(kr + 1, i + 1, { formula, valor }, {
      fuente: f(18, true, color), h: "center", borde: BORDE, formato: lbl === "% Cumplimiento" ? FMT_PCT : FMT_ENTERO,
    });
  });
  ws.alto(kr + 1, 28);

  r = kr + 3;
  ws.celda(r++, 1, "Por severidad (aplicables)", { fuente: f(12, true, NAVY) });
  ["Severidad", "Cumple", "Falla", "% Cumpl."].forEach((h, j) => ws.celda(r, j + 1, h, estiloEncabezado("center")));
  r++;
  const { R_SEV } = ctx.rangos;
  for (const sev of SEVERIDADES) {
    const deSev = noExcl.filter((x) => x.sev === sev);
    const ok = cuenta("Cumple", deSev);
    const bad = cuenta("Falla", deSev);
    ws.celda(r, 1, sev, { fuente: f(10, true, SEV_TXT[sev]), relleno: SEV_FILL[sev], borde: BORDE });
    ws.celda(r, 2, { formula: `COUNTIFS(${R_SEV},"${sev}",${R_EST},"Cumple",${R_EXC},"No")`, valor: ok }, { fuente: f(10), borde: BORDE, formato: FMT_ENTERO, h: "center" });
    ws.celda(r, 3, { formula: `COUNTIFS(${R_SEV},"${sev}",${R_EST},"Falla",${R_EXC},"No")`, valor: bad }, { fuente: f(10, true, BAD_TXT), borde: BORDE, formato: FMT_ENTERO, h: "center" });
    ws.celda(r, 4, { formula: `IFERROR(B${r}/(B${r}+C${r}),0)`, valor: ok + bad ? ok / (ok + bad) : 0 }, { fuente: f(10), borde: BORDE, formato: FMT_PCT, h: "center" });
    r++;
  }

  // Adopcion global ponderada por numero de reglas.
  const summary = data?.adoption_summary?.policies?.security_rule;
  const { total: totSummary, acc } = metricasPonderadas(Array.isArray(summary) ? summary : [], { excluirBpMode: true });
  const usandoFallback = totSummary <= 0 && fb.total > 0;
  const totalReglas = usandoFallback ? fb.total : totSummary;
  const pct = (k) => (usandoFallback ? fb.promedios[k] ?? null : totSummary > 0 && k in acc ? acc[k] / totSummary : null);

  if (totalReglas > 0) {
    r++;
    ws.celda(r++, 1, "Adopción de seguridad — global" + (usandoFallback ? "  —  reconstruido del config, sin 'adoption'/'adoption_summary'" : ""), {
      fuente: f(12, true, NAVY),
    });
    const destacados = [
      ["Reglas totales", totalReglas, FMT_ENTERO],
      ["App-ID habilitado", pct("app_id_enabled"), FMT_PCT_LITERAL],
      ["Log Forwarding", pct("log_forwarding_enabled"), FMT_PCT_LITERAL],
      ["Service definido", pct("service_port_configured"), FMT_PCT_LITERAL],
      ["Perfil Antivirus", pct("antivirus_profile_enabled"), FMT_PCT_LITERAL],
      ["Perfil Vulnerab.", pct("vulnerability_protection_profile_enabled"), FMT_PCT_LITERAL],
    ];
    for (const [k, v, fmt] of destacados) {
      ws.celda(r, 1, k, { fuente: f(10, true), relleno: GREY_H, borde: BORDE });
      ws.celda(r, 2, v ?? "—", { fuente: f(10), formato: fmt, borde: BORDE, h: "center" });
      r++;
    }
  }
}

function hojaHallazgos(libro, ctx) {
  const { filas, cliente } = ctx;
  const grupos = new Map();
  for (const x of filas) {
    if (x.estado !== "Falla" || x.excluido) continue;
    let e = grupos.get(x.id);
    if (!e) {
      e = { id: x.id, name: x.name, sev: x.sev, cat: x.cat, msg: "", ubic: new Set(), n: 0 };
      grupos.set(x.id, e);
    }
    if (x.msg && !e.msg) e.msg = x.msg;
    if (x.origen) e.ubic.add(x.origen);
    e.n++;
  }
  const distintos = [...grupos.values()].sort(
    (a, b) => (SEVORDEN[a.sev] ?? 9) - (SEVORDEN[b.sev] ?? 9) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
  );

  const ws = libro.hoja("Hallazgos").sinCuadricula();
  ws.combinar(1, 1, 1, 7).celda(1, 1, `Hallazgos — ${cliente}  ·  ${distintos.length} checks distintos en falla`, {
    fuente: f(14, true, WHITE), relleno: NAVY, h: "left", v: "center", sangria: 1,
  });
  ws.alto(1, 30);
  const cols = ["Severidad", "Check ID", "Hallazgo", "Categoría", "# afectados", `${ctx.lblPl} afectados`, "Acción / Mensaje"];
  cols.forEach((h, j) => ws.celda(2, j + 1, h, estiloEncabezado([1, 2, 5].includes(j + 1) ? "center" : "left")));

  const { R_ID, R_EST, R_EXC } = ctx.rangos;
  let r = 3;
  for (const e of distintos) {
    const txt = { fuente: f(9), borde: BORDE, v: "top", ajustar: true };
    ws.celda(r, 1, e.sev, { fuente: f(9, true, SEV_TXT[e.sev] || "000000"), relleno: SEV_FILL[e.sev] || WHITE, h: "center", v: "center", borde: BORDE });
    ws.celda(r, 2, e.id ?? "", { fuente: f(9), h: "center", v: "center", borde: BORDE });
    ws.celda(r, 3, e.name, txt);
    ws.celda(r, 4, e.cat, txt);
    const idSeguro = String(e.id ?? "").replace(/"/g, '""');
    ws.celda(r, 5, { formula: `COUNTIFS(${R_ID},"${idSeguro}",${R_EST},"Falla",${R_EXC},"No")`, valor: e.n }, {
      fuente: f(9, true), formato: FMT_ENTERO, h: "center", v: "center", borde: BORDE,
    });
    ws.celda(r, 6, e.ubic.size ? [...e.ubic].sort().join(", ") : "—", txt);
    ws.celda(r, 7, e.msg, txt);
    r++;
  }
  anchos(ws, [13, 9, 62, 14, 12, 40, 50]);
  ws.congelar("A3");
  filtroDesde(ws, 2, 7);
  return distintos.length;
}

const ADOP_COLS = [
  ["total_rule_count", "Reglas", false],
  ["app_id_enabled", "App-ID", true],
  ["user_id_enabled", "User-ID", true],
  ["service_port_configured", "Service", true],
  ["log_forwarding_enabled", "Log Fwd", true],
  ["antivirus_profile_enabled", "Antivirus", true],
  ["anti_spyware_profile_enabled", "Anti-Spyware", true],
  ["vulnerability_protection_profile_enabled", "Vuln.", true],
  ["url_filtering_profile_enabled", "URL Filt.", true],
  ["file_blocking_profile_enabled", "File Block", true],
  ["wildfire_analysis_profile_enabled", "WildFire", true],
  ["dns_security_enabled", "DNS Sec", true],
  ["credential_theft_enabled", "Cred. Theft", true],
];

function hojaAdopcion(libro, ctx) {
  const { data, fb } = ctx;
  const summary = data?.adoption_summary?.policies?.security_rule;
  let filas = (Array.isArray(summary) ? summary : [])
    .filter(esObjeto)
    .map((e) => [String(e.configuration?.location || "—"), e.metrics || {}])
    .sort((a, b) => (b[1].total_rule_count || 0) - (a[1].total_rule_count || 0) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const usandoFallback = !filas.length && fb.porUbicacion.length > 0;
  if (usandoFallback) filas = fb.porUbicacion;

  const ncol = ADOP_COLS.length + 1;
  const ws = libro.hoja("Adopcion seguridad").sinCuadricula();
  ws.combinar(1, 1, 1, ncol).celda(
    1, 1,
    `Adopción de seguridad — Security Policy por ${ctx.lbl.toLowerCase()}` +
      (usandoFallback ? "  —  reconstruido del config, sin 'adoption'/'adoption_summary'" : ""),
    { fuente: f(14, true, WHITE), relleno: NAVY, h: "left", v: "center", sangria: 1 }
  );
  ws.alto(1, 28);
  ws.combinar(2, 1, 2, ncol).celda(2, 1, "Verde ≥ 80%  ·  Rojo < 50%  ·  '—' = sin datos / sin reglas", {
    fuente: f(9, false, WHITE), relleno: ACCENT, h: "left", v: "center", sangria: 1,
  });
  [ctx.lbl, ...ADOP_COLS.map((c) => c[1])].forEach((h, j) => {
    ws.celda(3, j + 1, h, { fuente: f(9, true, WHITE), relleno: NAVY, borde: BORDE, h: j ? "center" : "left", v: "center", ajustar: true });
  });
  ws.alto(3, 26);

  let r = 4;
  for (const [loc, m] of filas) {
    dato(ws, r, 1, loc, { fuente: f(9, true) });
    ADOP_COLS.forEach(([clave, , esPct], j) => {
      const v = m[clave];
      if (v === null || v === undefined) {
        dato(ws, r, j + 2, "—", { fuente: f(9, false, NA_TXT), h: "center" });
      } else if (esPct && typeof v === "number") {
        dato(ws, r, j + 2, v, { fuente: f(9, v < 50, v >= 80 ? OK_TXT : v < 50 ? BAD_TXT : "000000"), h: "center", formato: FMT_PCT_LITERAL });
      } else {
        dato(ws, r, j + 2, v, { fuente: f(9, true), h: "center", formato: FMT_ENTERO });
      }
    });
    r++;
  }
  anchos(ws, [24, 11, ...Array(ADOP_COLS.length - 1).fill(10)]);
  ws.congelar("B4");
  filtroDesde(ws, 3, ncol);
}

const CAP_COLS = [
  ["app_id_enabled", "App-ID"],
  ["user_id_enabled", "User-ID"],
  ["log_forwarding_enabled", "Log Fwd"],
  ["antivirus_profile_enabled", "Antivirus"],
  ["anti_spyware_profile_enabled", "Anti-Spyware"],
  ["vulnerability_protection_profile_enabled", "Vuln."],
  ["url_filtering_profile_enabled", "URL Filt."],
  ["file_blocking_profile_enabled", "File Block"],
  ["wildfire_analysis_profile_enabled", "WildFire"],
  ["dns_security_enabled", "DNS Sec"],
  ["credential_theft_enabled", "Cred. Theft"],
];

function hojaReglas(libro, ctx) {
  const { data, fb } = ctx;
  const adoption = data?.adoption?.security_rule;
  const reglas = Array.isArray(adoption) ? adoption : [];
  const usandoFallback = !reglas.length && fb.filas.length > 0;

  let filas;
  if (usandoFallback) {
    filas = fb.filas.slice();
  } else {
    const AMP = [["applications", "App"], ["services", "Svc"], ["source_zones", "SrcZona"], ["source_addresses", "SrcAddr"], ["dest_addresses", "DstAddr"]];
    filas = reglas.filter(esObjeto).map((e) => {
      const c = e.configuration || {};
      const m = e.metrics || {};
      let faltan = 0;
      const caps = CAP_COLS.map(([k]) => {
        const v = m[k];
        if (v === 1 || v === true) return "Sí";
        if (v === 0 || v === false) {
          faltan++;
          return "No";
        }
        return "—";
      });
      const anys = AMP.filter(([campo]) => esAny(c[campo])).map(([, l]) => l);
      const seriales = (Array.isArray(c.targets) ? c.targets : [])
        .map((t) => String(t).split(":")[0])
        .filter((s) => !["", "None", "none"].includes(s));
      return {
        dg: String(c.location || "—"),
        regla: String(c.rule_name || c.name || "—"),
        accion: String(c.action || "—"),
        hab: c.rule_enabled === true || c.rule_enabled === 1 ? "Sí" : "No",
        faltan,
        caps,
        nany: anys.length,
        amp: anys.length ? anys.join(", ") : "—",
        serial: seriales.length ? seriales.join(", ") : "—",
        desc: String(c.description || "").trim() ? "Sí" : "No",
      };
    });
  }
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  filas.sort((a, b) => b.faltan - a.faltan || b.nany - a.nany || cmp(a.dg, b.dg) || cmp(a.regla, b.regla));

  const fijosIzq = [ctx.lbl, "Regla", "Acción", "Hab."];
  const fijosDer = ["Faltan", "# any", "Amplitud (any en)", "Serial(es)", "Desc."];
  const enc = [...fijosIzq, ...CAP_COLS.map((c) => c[1]), ...fijosDer];
  const n = enc.length;
  const cap0 = fijosIzq.length + 1;
  const capN = cap0 + CAP_COLS.length - 1;
  const [cFaltan, cNany, cAmp, cSerial, cDesc] = [1, 2, 3, 4, 5].map((i) => capN + i);

  const ws = libro.hoja("Reglas").sinCuadricula();
  ws.combinar(1, 1, 1, n).celda(
    1, 1,
    `Reglas — adopción y amplitud por regla  ·  ${filas.length} reglas` +
      (usandoFallback ? "  —  reconstruido del config, sin 'adoption'/'adoption_summary'" : ""),
    { fuente: f(14, true, WHITE), relleno: NAVY, h: "left", v: "center", sangria: 1 }
  );
  ws.alto(1, 28);
  ws.combinar(2, 1, 2, n).celda(
    2, 1,
    "Capacidades: Sí = la aplica, No = le falta  ·  Amplitud: campos en 'any' (filtra Acción=allow para exposición real)  ·  ordenadas por # faltantes",
    { fuente: f(9, false, WHITE), relleno: ACCENT, h: "left", v: "center", sangria: 1 }
  );
  const izq = new Set([1, 2, 3, cAmp, cSerial]);
  enc.forEach((h, j) => ws.celda(3, j + 1, h, { fuente: f(9, true, WHITE), relleno: NAVY, borde: BORDE, h: izq.has(j + 1) ? "left" : "center", v: "center", ajustar: true }));
  ws.alto(3, 26);

  let r = 4;
  for (const x of filas) {
    [x.dg, x.regla, x.accion, x.hab].forEach((v, j) =>
      dato(ws, r, j + 1, v, { fuente: f(9, j === 1), h: j < 2 ? "left" : "center", ajustar: j === 1 })
    );
    x.caps.forEach((cap, j) =>
      dato(ws, r, cap0 + j, cap, { fuente: f(9, cap === "No", cap === "No" ? BAD_TXT : cap === "Sí" ? OK_TXT : NA_TXT), h: "center" })
    );
    dato(ws, r, cFaltan, x.faltan, { fuente: f(9, true, x.faltan ? BAD_TXT : OK_TXT), h: "center" });
    dato(ws, r, cNany, x.nany, { fuente: f(9, x.nany > 0, x.nany ? BAD_TXT : NA_TXT), h: "center" });
    dato(ws, r, cAmp, x.amp, { fuente: f(9, false, x.amp !== "—" ? BAD_TXT : NA_TXT) });
    dato(ws, r, cSerial, x.serial);
    dato(ws, r, cDesc, x.desc, { fuente: f(9, false, x.desc === "No" ? NA_TXT : "000000"), h: "center" });
    r++;
  }
  anchos(ws, [22, 38, 9, 6, ...Array(CAP_COLS.length).fill(10), 7, 7, 18, 20, 7]);
  ws.congelar("C4");
  filtroDesde(ws, 3, n);
}

function hojaBpMode(libro, ctx) {
  const { data, fb, grupos } = ctx;
  const summary = data?.adoption_summary?.policies?.security_rule;
  const { total, acc } = metricasPonderadas(Array.isArray(summary) ? summary : [], { excluirBpMode: false });
  const usandoFallback = total <= 0 && Object.keys(fb.promedios).length > 0 && fb.total > 0;

  const bp = usandoFallback ? bpModeFallback(data, grupos, fb.total) : { porcentajes: {}, gruposSinResolver: 0 };

  const habilitado = (k) => (usandoFallback ? fb.promedios[k] ?? null : total > 0 && k in acc ? r1(acc[k] / total) : null);
  const enBpMode = (k) => {
    if (usandoFallback) {
      if (k === "log_end") return fb.promedios[k] ?? null;
      return bp.porcentajes[k.replace(/_bp_mode$/, "")] ?? null;
    }
    return total > 0 && k in acc ? r1(acc[k] / total) : null;
  };

  const CATS = [
    ["Antivirus", "antivirus_profile_enabled"],
    ["Anti-Spyware", "anti_spyware_profile_enabled"],
    ["Vulnerability", "vulnerability_protection_profile_enabled"],
    ["URL Filtering", "url_filtering_profile_enabled"],
    ["File Blocking", "file_blocking_profile_enabled"],
    ["WildFire", "wildfire_analysis_profile_enabled"],
    ["DNS Security", "dns_security_enabled"],
    ["Credential Theft", "credential_theft_enabled"],
  ];
  const filas = [
    ...CATS.map(([lbl, k]) => [lbl, habilitado(k), enBpMode(`${k}_bp_mode`)]),
    ["Logging", habilitado("log_end"), enBpMode("log_end")],
  ];
  const valoresBp = filas.map((x) => x[2]).filter((v) => v !== null);
  const promedio = valoresBp.length ? r1(valoresBp.reduce((s, v) => s + v, 0) / valoresBp.length) : null;

  const ws = libro.hoja("BP Mode").sinCuadricula();
  ws.combinar(1, 1, 1, 10).celda(
    1, 1,
    "Best Practices — adopción vs BP Mode (araña)" + (usandoFallback ? "  —  reconstruido del config, sin 'adoption_summary'" : ""),
    { fuente: f(14, true, WHITE), relleno: NAVY, h: "left", v: "center", sangria: 1 }
  );
  ws.alto(1, 28);

  let sub =
    `Promedio en BP Mode: ${promedio !== null ? `${promedio.toFixed(1)}%` : "— (sin datos de 'En BP Mode')"}  ·  ` +
    "'Habilitado' = la regla tiene el perfil; 'En BP Mode' = el perfil sigue las mejores prácticas (acciones recomendadas)";
  if (usandoFallback) {
    sub += "  ·  'En BP Mode' reconstruido cruzando perfil-por-regla vs. cumplimiento BPA del perfil (hoja Perfiles)";
    const hayGrupos = grupos && Object.keys(grupos).length > 0;
    if (hayGrupos) sub += "; grupos de perfiles resueltos con el running-config.xml aportado";
    if (bp.gruposSinResolver) {
      sub +=
        `; ${bp.gruposSinResolver} regla(s) con Security Profile Group ` +
        (hayGrupos ? "no resuelto en el XML" : "(sube el running-config.xml para incluirlas)") +
        " quedan excluidas del cálculo";
    }
  }
  ws.combinar(2, 1, 2, 10).celda(2, 1, sub, { fuente: f(9, false, WHITE), relleno: ACCENT, h: "left", v: "center", sangria: 1 });

  ["Categoría", "Habilitado", "En BP Mode"].forEach((h, j) => ws.celda(3, j + 1, h, estiloEncabezado(j ? "center" : "left")));
  let r = 4;
  for (const [lbl, hab, bpm] of filas) {
    dato(ws, r, 1, lbl, { fuente: f(10) });
    [[2, hab], [3, bpm]].forEach(([col, v]) => {
      if (v === null) {
        dato(ws, r, col, "—", { fuente: f(10, false, NA_TXT), h: "center" });
      } else {
        const color = v >= 80 ? OK_TXT : v < 50 ? BAD_TXT : WARN_TXT;
        dato(ws, r, col, v, { fuente: f(10, col === 3 && v < 50, color), h: "center", formato: FMT_PCT_LITERAL });
      }
    });
    r++;
  }
  const ultima = r - 1;
  ws.celda(r, 1, "Promedio (BP Mode)", { fuente: f(10, true, NAVY), relleno: GREY_H, borde: BORDE });
  ws.celda(r, 2, null, { relleno: GREY_H, borde: BORDE });
  ws.celda(r, 3, promedio ?? "—", {
    fuente: f(11, true, promedio !== null ? ACCENT : NA_TXT), relleno: GREY_H, borde: BORDE, h: "center",
    formato: promedio !== null ? FMT_PCT_LITERAL : undefined,
  });
  anchos(ws, [20, 13, 13]);

  ws.radar({
    titulo: "Habilitado vs En BP Mode por categoría",
    categorias: { fila1: 4, fila2: ultima, col: 1 },
    series: [
      { nombreFila: 3, col: 2, color: ACCENT },
      { nombreFila: 3, col: 3, color: "C0504D" },
    ],
    ancla: "E3",
    escala: { min: 0, max: 100 },
  });
}

function hojaDecryption(libro, ctx) {
  const pol = ctx.data?.best_practices?.policies || {};
  let filas = (pol.decryption_rule || []).filter(esObjeto).map((it) => {
    const c = it.configuration || {};
    const falta = checksEnFalla(it);
    return {
      dg: String(c.location || "—"), regla: String(c.name || "—"), accion: String(c.action || "—"),
      tipo: String(c.rule_type || "—"), perfil: String(c.decryption_profile || "—"),
      estado: falta.length ? "Falla" : "Cumple", falta: falta.length ? unir(falta) : "—",
    };
  });

  // Sin reglas individuales la API a veces solo trae el check del rulebase.
  let soloRulebase = false;
  if (!filas.length) {
    const vistos = new Set();
    for (const it of (pol.decryption_rulebase || []).filter(esObjeto)) {
      const falta = checksEnFalla(it);
      if (!falta.length) continue;
      const loc = String(it.configuration?.location || "—");
      const clave = `${loc} ${unir(falta)}`;
      if (vistos.has(clave)) continue;
      vistos.add(clave);
      filas.push({ dg: loc, regla: "(nivel rulebase — sin reglas individuales)", accion: "—", tipo: "—", perfil: "—", estado: "Falla", falta: unir(falta) });
    }
    soloRulebase = filas.length > 0;
  }
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  filas.sort((a, b) => (a.estado !== "Falla") - (b.estado !== "Falla") || cmp(a.dg, b.dg) || cmp(a.regla, b.regla));
  const nf = filas.filter((x) => x.estado === "Falla").length;

  const ws = hojaBase(
    libro, "Decryption",
    `Reglas de descifrado — ${filas.length} · ${nf} con hallazgos`,
    soloRulebase
      ? "No hay reglas de descifrado individuales en el JSON; se muestra el hallazgo a nivel de rulebase (ej. falta una política de descifrado con Decryption Profile)."
      : "Qué falta = checks del BPA en falla para esa regla (ej. perfil de descifrado no adjunto)",
    [ctx.lbl, "Regla", "Acción", "Tipo", "Perfil de descifrado", "Estado", "Qué falta"],
    [1, 2, 5, 7]
  );
  let r = 4;
  for (const x of filas) {
    const sinPerfil = ["none", "—", ""].includes(x.perfil.trim().toLowerCase());
    [x.dg, x.regla, x.accion, x.tipo, x.perfil].forEach((v, j) => {
      const col = j + 1;
      dato(ws, r, col, v, {
        fuente: col === 5 && sinPerfil ? f(9, true, BAD_TXT) : f(9, col === 2),
        h: [1, 2, 5].includes(col) ? "left" : "center",
      });
    });
    dato(ws, r, 6, x.estado, { fuente: f(9, true, x.estado === "Falla" ? BAD_TXT : OK_TXT), h: "center" });
    dato(ws, r, 7, x.falta, { fuente: f(9, false, x.falta !== "—" ? "000000" : NA_TXT), v: "top", ajustar: true });
    r++;
  }
  anchos(ws, [22, 30, 12, 18, 22, 10, 46]);
  avisoSiVacio(ws, r, 7);
  filtroDesde(ws, 3, 7);
}

const MESES = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

/** "Jan  5 12:00:00 2027 GMT" -> Date (hora local, como strptime en la skill). */
export function parsearExpiracion(texto) {
  const m = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})/.exec(String(texto).replace(" GMT", "").trim());
  if (!m || !(m[1].toLowerCase() in MESES)) return null;
  return new Date(Number(m[6]), MESES[m[1].toLowerCase()], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
}

function hojaCertificados(libro, ctx) {
  const bp = ctx.data?.best_practices || {};
  const vistos = new Set();
  const certs = [];
  for (const cat of ["panorama", "device", "objects"]) {
    for (const it of bp[cat]?.certificate || []) {
      const c = it?.configuration || {};
      if (!c.name) continue;
      const clave = JSON.stringify([c.name, c.expiry, c.location]);
      if (vistos.has(clave)) continue;
      vistos.add(clave);
      certs.push(c);
    }
  }
  const ahora = ctx.ahora;
  const filas = certs.map((c) => {
    const dt = c.expiry ? parsearExpiracion(c.expiry) : null;
    let estado = "Sin fecha";
    let dias = null;
    if (dt) {
      dias = Math.floor((dt - ahora) / 86400000);
      estado = dias < 0 ? "Vencido" : dias <= 90 ? "Por vencer" : "Vigente";
    }
    return { name: String(c.name), loc: String(c.location || "—"), exp: String(c.expiry || "—"), dias, estado };
  });
  const orden = { Vencido: 0, "Por vencer": 1, Vigente: 2, "Sin fecha": 3 };
  filas.sort((a, b) => orden[a.estado] - orden[b.estado] || (a.dias ?? 999999) - (b.dias ?? 999999));
  const nv = filas.filter((x) => x.estado === "Vencido").length;
  const npv = filas.filter((x) => x.estado === "Por vencer").length;

  const ws = hojaBase(
    libro, "Certificados",
    `Certificados — ${filas.length} · ${nv} vencidos · ${npv} por vencer (≤90 días)`,
    "Vencido = ya expiró · Por vencer = expira en 90 días o menos",
    ["Certificado", "Ubicación", "Expira", "Días", "Estado"],
    [1, 2, 3]
  );
  const rellenoEstado = { Vencido: SEV_FILL["Crítico"], "Por vencer": SEV_FILL["Advertencia"], Vigente: "E7F4EA", "Sin fecha": NA_FILL };
  const txtEstado = { Vencido: BAD_TXT, "Por vencer": WARN_TXT, Vigente: OK_TXT, "Sin fecha": NA_TXT };
  let r = 4;
  for (const x of filas) {
    const urgente = x.estado === "Vencido" || x.estado === "Por vencer";
    dato(ws, r, 1, x.name);
    dato(ws, r, 2, x.loc);
    dato(ws, r, 3, x.exp);
    dato(ws, r, 4, x.dias ?? "—", { h: "center", fuente: urgente ? f(9, true, txtEstado[x.estado]) : f(9) });
    dato(ws, r, 5, x.estado, { h: "center", relleno: rellenoEstado[x.estado], fuente: f(9, true, txtEstado[x.estado]) });
    r++;
  }
  anchos(ws, [34, 16, 22, 9, 13]);
  avisoSiVacio(ws, r, 5,
    "Sin certificados en el JSON del BPA (best_practices.*.certificate viene vacío). Normalmente significa que el " +
      "dispositivo no tiene certificados propios en el config subido, no que falten datos por un error del reporte.");
  filtroDesde(ws, 3, 5);
}

function hojaZonas(libro, ctx) {
  const zonas = ctx.data?.best_practices?.network?.zone || [];
  const siNo = (v) => (v === true || v === 1 ? "Sí" : "No");
  const filas = zonas.filter(esObjeto).map((it) => {
    const c = it.configuration || {};
    const falta = checksEnFalla(it);
    return {
      tpl: String(c.template_name || c.location || "—"), zona: String(c.name || "—"),
      zp: String(c.zone_protection_profile || "—"), sinZp: !c.zone_protection_profile,
      pbp: siNo(c.packet_buffer_protection_enabled), uid: siNo(c.user_id_enabled),
      estado: falta.length ? "Falla" : "Cumple", falta: falta.length ? unir(falta) : "—",
    };
  });
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  filas.sort((a, b) => (a.estado !== "Falla") - (b.estado !== "Falla") || cmp(a.tpl, b.tpl) || cmp(a.zona, b.zona));
  const nf = filas.filter((x) => x.estado === "Falla").length;

  const ws = hojaBase(
    libro, "Zonas",
    `Zonas — ${filas.length} · ${nf} con hallazgos`,
    "Qué falta = checks del BPA en falla (Zone Protection, Packet Buffer, User-ID ACL include list)",
    ["Template", "Zona", "Zone Protection", "Packet Buffer", "User-ID", "Estado", "Qué falta"],
    [1, 2, 3, 7]
  );
  let r = 4;
  for (const x of filas) {
    dato(ws, r, 1, x.tpl);
    dato(ws, r, 2, x.zona);
    dato(ws, r, 3, x.zp, { fuente: x.sinZp ? f(9, true, BAD_TXT) : f(9) });
    dato(ws, r, 4, x.pbp, { h: "center", fuente: x.pbp === "No" ? f(9, false, NA_TXT) : f(9) });
    dato(ws, r, 5, x.uid, { h: "center" });
    dato(ws, r, 6, x.estado, { h: "center", fuente: f(9, true, x.estado === "Falla" ? BAD_TXT : OK_TXT) });
    dato(ws, r, 7, x.falta, { fuente: f(9, false, x.falta !== "—" ? "000000" : NA_TXT), v: "top", ajustar: true });
    r++;
  }
  anchos(ws, [24, 24, 24, 12, 9, 10, 46]);
  avisoSiVacio(ws, r, 7);
  filtroDesde(ws, 3, 7);
}

function hojaPerfiles(libro, ctx) {
  const { data, grupos } = ctx;
  const bp = data?.best_practices || {};
  const objs = bp.objects || {};
  const TIPOS = [
    ["antivirus_profile", "Antivirus"], ["anti_spyware_profile", "Anti-Spyware"],
    ["vulnerability_protection_profile", "Vulnerability"], ["url_filtering_profile", "URL Filtering"],
    ["file_blocking_profile", "File Blocking"], ["wildfire_analysis_profile", "WildFire"],
    ["data_filtering_profile", "Data Filtering"], ["dns_security_profile", "DNS Security"],
    ["decryption_profile", "Decryption"], ["zone_protection_profile", "Zone Protection"],
    ["log_forwarding_profile", "Log Forwarding"],
  ];
  const CAMPOS = [
    "profile_antivirus", "profile_anti_spyware", "profile_vulnerability_protection", "profile_url_filtering",
    "profile_file_blocking", "profile_wildfire_analysis", "profile_virus_and_wildfire_analysis",
    "profile_data_filtering", "profile_dns_security", "log_setting",
  ];

  const usados = new Set();
  const gruposUsados = new Map();
  let reglasConGrupo = 0;
  for (const e of reglasSeguridad(data)) {
    const c = e?.configuration || {};
    for (const k of CAMPOS) if (c[k]) usados.add(String(c[k]));
    const g = c.profile_setting?.group;
    const lista = Array.isArray(g) ? g : g ? [g] : [];
    if (lista.length) {
      reglasConGrupo++;
      for (const nombre of lista) gruposUsados.set(String(nombre), (gruposUsados.get(String(nombre)) || 0) + 1);
    }
  }
  for (const e of data?.adoption?.security_rule || []) {
    const c = e?.configuration || {};
    for (const k of [
      "profile_antivirus", "profile_anti_spyware", "profile_vulnerability_protection", "profile_url_filtering",
      "profile_file_blocking", "profile_wildfire_analysis", "profile_data_filtering", "profile_dns_security",
      "profile_antivirus_wildfire_analysis", "log_forwarding_profile",
    ]) if (c[k]) usados.add(String(c[k]));
  }

  // Con el running-config.xml, los perfiles dentro de los grupos usados
  // tambien cuentan como en uso (la skill no podia saberlo sin el XML).
  const usadosViaGrupo = new Set();
  if (grupos) {
    for (const nombre of gruposUsados.keys()) {
      for (const perfil of Object.values(grupos[nombre] || {})) usadosViaGrupo.add(String(perfil));
    }
  }

  let sub;
  if (gruposUsados.size) {
    const txt = [...gruposUsados.entries()].sort((a, b) => b[1] - a[1]).map(([g, n]) => `${g} (${n})`).join(", ");
    sub = grupos && Object.keys(grupos).length
      ? `${reglasConGrupo} regla(s) usan Security Profile Groups (${txt}). Los grupos se resolvieron con el running-config.xml: ` +
        "'Usado' incluye los perfiles que están dentro de esos grupos."
      : `${reglasConGrupo} regla(s) usan Security Profile Groups (${txt}) en vez de perfiles individuales. Este JSON no incluye ` +
        "la definición de esos grupos, así que 'Usado' no puede confirmar si un perfil marcado 'No' está dentro de uno de ellos — " +
        "aporta el running-config.xml o revisa esos grupos antes de borrar cualquier perfil en 'No'.";
  } else {
    sub = "'Usado' = alguna regla referencia este perfil individualmente (no vía profile-group). " +
      "'Cumple BPA' es independiente: indica si el perfil pasa sus propios checks del BPA.";
  }

  const ws = hojaBase(libro, "Perfiles", "Inventario de perfiles de seguridad", sub,
    ["Tipo", "Perfil", "Ubicación", "Usado en una regla", "Cumple BPA", "Qué falta"], [1, 2, 3, 6]);
  let r = 4;
  for (const [clave, etiqueta] of TIPOS) {
    for (const it of objs[clave] || []) {
      const c = it?.configuration || {};
      if (!c.name) continue;
      const nombre = String(c.name);
      const uso = usados.has(nombre) ? "Sí" : usadosViaGrupo.has(nombre) ? "Sí (grupo)" : "No";
      const falta = checksEnFalla(it);
      dato(ws, r, 1, etiqueta);
      dato(ws, r, 2, nombre);
      dato(ws, r, 3, String(c.location || "—"));
      dato(ws, r, 4, uso, { h: "center", fuente: uso === "No" ? f(9, false, NA_TXT) : f(9) });
      dato(ws, r, 5, falta.length ? "Falla" : "Cumple", { h: "center", fuente: f(9, true, falta.length ? BAD_TXT : OK_TXT) });
      dato(ws, r, 6, falta.length ? unir(falta) : "—", { v: "top", ajustar: true, fuente: f(9, false, falta.length ? "000000" : NA_TXT) });
      r++;
    }
  }
  anchos(ws, [16, 34, 16, 20, 11, 46]);
  avisoSiVacio(ws, r, 6);
  filtroDesde(ws, 3, 6);
}

function hojaPlataforma(libro, ctx) {
  const bp = ctx.data?.best_practices || {};
  const ws = libro.hoja("Plataforma").sinCuadricula();
  ws.combinar(1, 1, 1, 6).celda(1, 1, "Plataforma — administración y mantenimiento", { fuente: f(14, true, WHITE), relleno: NAVY, h: "left", v: "center", sangria: 1 });
  ws.alto(1, 28);

  const seccion = (fila, titulo, encabezados, izq) => {
    ws.celda(fila, 1, titulo, { fuente: f(12, true, NAVY) });
    encabezados.forEach((h, j) => ws.celda(fila + 1, j + 1, h, estiloEncabezado(izq.includes(j + 1) ? "left" : "center")));
    return fila + 2;
  };
  const txt = (v) => (v === null || v === undefined || v === "" ? "—" : String(v));
  const esYes = (v) => String(v ?? "").trim().toLowerCase() === "yes";

  // Administradores (dedupe por nombre + rol + perfiles).
  const admins = new Map();
  for (const it of bp.device?.administrator || []) {
    for (const a of it?.configuration?.admins || []) {
      admins.set(JSON.stringify([a.name, a.role, a.authentication_profile, a.password_profile]), a);
    }
  }
  const adm = [...admins.values()];
  const nSuper = adm.filter((a) => a.role === "superuser").length;
  let r = seccion(3, `Administradores (${adm.length} únicos · ${nSuper} superuser)`,
    ["Usuario", "Rol", "Auth profile", "Password profile", "Observación"], [1, 3, 4, 5]);
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  adm.sort((a, b) => cmp(a.role || "", b.role || "") || cmp(a.name || "", b.name || ""));
  for (const a of adm) {
    const obs = [];
    if (!a.password_profile) obs.push("Sin password profile");
    if (a.role === "superuser" && !a.authentication_profile) obs.push("Superuser sin auth profile");
    [txt(a.name), txt(a.role), txt(a.authentication_profile), txt(a.password_profile)].forEach((v, j) =>
      dato(ws, r, j + 1, v, { h: j === 1 ? "center" : "left" })
    );
    dato(ws, r, 5, obs.length ? obs.join("; ") : "—", { fuente: obs.length ? f(9, false, WARN_TXT) : f(9) });
    r++;
  }
  if (!adm.length) {
    ws.combinar(r, 1, r, 5).celda(r, 1,
      "Sin administradores locales en el JSON del BPA (puede ser normal si la autenticación es vía directorio/SAML en vez de cuentas locales).",
      { fuente: f(9, false, NA_TXT), h: "left", v: "center", sangria: 1 });
    r++;
  }
  r++;

  r = seccion(r, `Alta disponibilidad (HA) — ${ctx.lbl}`, [ctx.lbl, "HA habilitado", "Modo", "Config sync", "Qué falta"], [1, 5]);
  for (const it of bp.device?.high_availability || []) {
    const c = it?.configuration || {};
    const g = c.group || {};
    const hab = esYes(c.enabled) ? "Sí" : "No";
    const modo = esObjeto(g.mode) ? Object.keys(g.mode)[0] || "—" : txt(g.mode);
    const sync = esYes(g.configuration_synchronization?.enabled) ? "Sí" : "No";
    const falta = checksEnFalla(it);
    dato(ws, r, 1, txt(c.location || c.template_name));
    dato(ws, r, 2, hab, { h: "center", fuente: hab === "No" ? f(9, true, BAD_TXT) : f(9) });
    dato(ws, r, 3, modo, { h: "center" });
    dato(ws, r, 4, sync, { h: "center" });
    dato(ws, r, 5, falta.length ? unir(falta) : "—", { v: "top", ajustar: true });
    r++;
  }
  r++;

  const formatoDu = (entry) => {
    if (!entry) return "—";
    const rec = entry.recurring || {};
    if (rec.daily) return `${rec.daily.action || "?"} @ ${rec.daily.at || "?"}`;
    // Otras frecuencias (hourly, every-30-mins, real-time...): la evaluacion
    // local las trae tal cual vienen en el XML.
    const [frecuencia, detalle] = Object.entries(rec).find(([k, v]) => k !== "sync_to_peer" && esObjeto(v)) || [];
    if (frecuencia) return [detalle.action, frecuencia].filter(Boolean).join(" · ");
    if ("sync_to_peer" in rec) return String(rec.sync_to_peer).toLowerCase() === "yes" ? "Solo sync a peer" : "Sin recurrencia";
    return "Sin recurrencia";
  };
  r = seccion(r, `Actualizaciones dinámicas — ${ctx.lbl} (recurrencia / acción)`, [ctx.lbl, "Antivirus", "Amenazas", "WildFire", "Qué falta"], [1, 5]);
  for (const it of bp.device?.dynamic_updates || []) {
    const c = it?.configuration || {};
    const falta = checksEnFalla(it);
    dato(ws, r, 1, txt(c.location || c.template_name));
    dato(ws, r, 2, formatoDu(c.anti_virus), { h: "center" });
    dato(ws, r, 3, formatoDu(c.threats), { h: "center" });
    dato(ws, r, 4, formatoDu(c.wildfire || c.wf_private), { h: "center" });
    dato(ws, r, 5, falta.length ? unir(falta) : "—", { v: "top", ajustar: true });
    r++;
  }
  r++;

  r = seccion(r, "Perfiles de Log Forwarding", ["Perfil", "Ubicación", "Destinos (syslog)", "Tipos de log"], [1, 2, 3, 4]);
  for (const it of bp.objects?.log_forwarding_profile || []) {
    const c = it?.configuration || {};
    const destinos = new Set();
    const tipos = new Set();
    for (const s of c.match_list || c.settings || []) {
      for (const d of s?.send_syslog || s?.syslog || []) destinos.add(String(d));
      if (s?.log_type) tipos.add(String(s.log_type));
    }
    dato(ws, r, 1, txt(c.name));
    dato(ws, r, 2, txt(c.location));
    dato(ws, r, 3, [...destinos].sort().join(", ") || "—", { ajustar: true });
    dato(ws, r, 4, [...tipos].sort().join(", ") || "—", { ajustar: true });
    r++;
  }
  anchos(ws, [30, 18, 18, 18, 50, 16]);
}

function hojaDetalle(libro, filas) {
  const ws = libro.hoja("Detalle");
  const cols = ["Categoría", "Área", "Origen", "Objeto", "Check ID", "Check", "Severidad", "Estado", "Excluido", "Mensaje"];
  cols.forEach((h, j) => ws.celda(1, j + 1, h, estiloEncabezado("left")));
  filas.forEach((x, i) => {
    const r = i + 2;
    const base = { relleno: zebra(r), borde: BORDE, v: "top" };
    [x.cat, x.sub, x.origen, x.objeto, x.id ?? "", x.name, x.sev].forEach((v, j) =>
      ws.celda(r, j + 1, v, { ...base, fuente: f(9), ajustar: [4, 6].includes(j + 1) })
    );
    const colorEstado = x.estado === "Falla" ? f(9, true, BAD_TXT) : x.estado === "Cumple" ? f(9, false, OK_TXT) : f(9, false, NA_TXT);
    ws.celda(r, 8, x.estado, { ...base, fuente: colorEstado });
    ws.celda(r, 9, x.excluido ? "Sí" : "No", { ...base, fuente: f(9) });
    ws.celda(r, 10, x.msg, { ...base, fuente: f(9), ajustar: true });
  });
  anchos(ws, [16, 26, 18, 30, 9, 50, 13, 11, 10, 46]);
  ws.congelar("A2");
  ws.filtro(`A1:J${filas.length + 1}`);
}

// ---------------------------------------------------------------------------
//  Punto de entrada
// ---------------------------------------------------------------------------

/**
 * @param {object} data     raiz del BPA (con best_practices)
 * @param {object} opciones
 * @param {string} opciones.cliente
 * @param {object} [opciones.grupos]  salida de parsearGruposPerfiles()
 * @param {Date}   [opciones.ahora]   referencia para los dias de certificados
 * @returns {{bytes: Uint8Array, checks: number, hallazgos: number, reconstruido: boolean}}
 */
export function generarExcelBpa(data, { cliente, grupos = null, ahora = new Date() } = {}) {
  const filas = cargarChecks(data);
  const panorama = esPanorama(data);

  const tieneAdoption = Boolean(data?.adoption?.security_rule?.length);
  const tieneSummary = Boolean(data?.adoption_summary?.policies?.security_rule?.length);
  const reconstruido = !(tieneAdoption && tieneSummary);
  const fb = reconstruido ? reglasFallback(data, grupos) : { filas: [], porUbicacion: [], promedios: {}, total: 0 };

  const ultima = filas.length + 1;
  const ctx = {
    data, cliente, filas, fb, grupos, ahora, panorama,
    local: data?.information?.origen === "local",
    lbl: panorama ? "Device group" : "Ubicación",
    lblPl: panorama ? "Device groups" : "Ubicaciones",
    rangos: {
      R_ID: `Detalle!$E$2:$E$${ultima}`,
      R_SEV: `Detalle!$G$2:$G$${ultima}`,
      R_EST: `Detalle!$H$2:$H$${ultima}`,
      R_EXC: `Detalle!$I$2:$I$${ultima}`,
    },
  };

  const libro = new Libro();
  hojaResumen(libro, ctx);
  const hallazgos = hojaHallazgos(libro, ctx);
  hojaAdopcion(libro, ctx);
  hojaReglas(libro, ctx);
  hojaBpMode(libro, ctx);
  hojaDecryption(libro, ctx);
  hojaCertificados(libro, ctx);
  hojaZonas(libro, ctx);
  hojaPerfiles(libro, ctx);
  hojaPlataforma(libro, ctx);
  hojaDetalle(libro, filas);

  return { bytes: libro.aBytes(), checks: filas.length, hallazgos, reconstruido };
}

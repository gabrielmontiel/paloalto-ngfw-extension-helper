// js/lib/bpaReport.js
// Lectura del JSON de un Best Practice Assessment (SCM Posture API) y
// generacion del reporte HTML. Port de load_checks() y build_html() del
// script Python de BPA original, con marca neutral PAN Helper.
//
// Modulo puro: no toca el DOM, la red ni chrome.*. Recibe objetos y devuelve
// objetos o texto, asi se puede probar fuera del navegador.
//
// Formato de entrada (best_practices):
//   best_practices.<categoria>.<subcategoria> = [ { configuration, warnings[] } ]
//   cada warning: check_id, check_name, check_type, check_passed,
//                 check_excluded, user_excluded, check_message
// El modo local del modulo produce este mismo formato, asi que todo lo que
// sigue sirve para los tres origenes (JSON existente, SCM y local).

export const SEVERIDADES = ["Crítico", "Advertencia", "Informativo"];

const SEVMAP = { Critical: "Crítico", Warning: "Advertencia", Informational: "Informativo" };
const SEVORDEN = { "Crítico": 0, "Advertencia": 1, "Informativo": 2 };

/** true/"true"/"True" -> true. La API mezcla booleanos y texto. */
function esVerdadero(v) {
  return v === true || String(v).toLowerCase() === "true";
}

/**
 * Busca el objeto que contiene 'best_practices' dentro de cualquier
 * envoltura ({status, result:{...}}) o de un campo que traiga JSON como texto.
 * @returns {object|null}
 */
export function localizarRaizBpa(obj, profundidad = 0) {
  if (profundidad > 8 || obj === null || typeof obj !== "object") return null;

  if (Array.isArray(obj)) {
    for (const v of obj) {
      const r = localizarRaizBpa(v, profundidad + 1);
      if (r) return r;
    }
    return null;
  }

  if ("best_practices" in obj) return obj;

  for (let v of Object.values(obj)) {
    if (typeof v === "string" && v.includes("best_practices")) {
      try {
        v = JSON.parse(v);
      } catch {
        continue;
      }
    }
    const r = localizarRaizBpa(v, profundidad + 1);
    if (r) return r;
  }
  return null;
}

/**
 * Parsea el texto de un archivo y devuelve la raiz del BPA.
 * Lanza un Error legible si no es un BPA.
 */
export function parsearJsonBpa(texto) {
  let cargado;
  try {
    cargado = JSON.parse(texto);
  } catch (e) {
    throw new Error(`El archivo no es JSON valido: ${e.message}`);
  }

  const data = localizarRaizBpa(cargado);
  if (!data) {
    const claves =
      cargado && typeof cargado === "object" && !Array.isArray(cargado)
        ? Object.keys(cargado).join(", ")
        : Array.isArray(cargado) ? "(lista)" : typeof cargado;
    throw new Error(
      "No se encontro 'best_practices' en el JSON. Verifica que sea el resultado " +
        `del BPA y no otro archivo. Claves de nivel superior: ${claves}.`
    );
  }
  return data;
}

/**
 * Aplana best_practices en una fila por check evaluado.
 * @returns {Array<{cat, sub, origen, objeto, id, name, sev, estado, excluido, msg}>}
 */
export function cargarChecks(data) {
  const bp = data?.best_practices;
  if (!bp || typeof bp !== "object") {
    throw new Error("El JSON no tiene la clave 'best_practices'.");
  }

  const filas = [];
  for (const [cat, subs] of Object.entries(bp)) {
    if (!subs || typeof subs !== "object" || Array.isArray(subs)) continue;

    for (const [sub, items] of Object.entries(subs)) {
      if (!Array.isArray(items)) continue;

      for (const it of items) {
        if (!it || typeof it !== "object") continue;
        const cfg = it.configuration || {};
        const origen = String(cfg.location ?? "").trim();
        const objeto = String(cfg.name ?? "").trim();

        for (const w of it.warnings || []) {
          if (!w || typeof w !== "object") continue;

          const cp = w.check_passed;
          let estado;
          if (cp === null || cp === undefined || String(cp).toLowerCase() === "none") estado = "No aplica";
          else if (esVerdadero(cp)) estado = "Cumple";
          else estado = "Falla";

          const msg = w.check_message;
          filas.push({
            cat,
            sub,
            origen,
            objeto,
            id: w.check_id,
            name: String(w.check_name ?? "").trim(),
            sev: SEVMAP[w.check_type] || w.check_type || "",
            estado,
            excluido: esVerdadero(w.check_excluded) || esVerdadero(w.user_excluded),
            msg: msg === null || msg === undefined || String(msg).trim().toLowerCase() === "none"
              ? ""
              : String(msg).trim(),
          });
        }
      }
    }
  }
  return filas;
}

/**
 * Panorama (device groups) o firewall standalone. Senales: platform ==
 * 'panorama', entradas 'DG-*' en level_order, o template-stack.
 */
export function esPanorama(data) {
  const info = data?.information || {};
  if (String(info.platform ?? "").trim().toLowerCase() === "panorama") return true;
  const lo = Array.isArray(info.level_order) ? info.level_order : [];
  if (lo.some((x) => typeof x === "string" && x.startsWith("DG-"))) return true;
  return Boolean(info["template-stack"] || info.template_stack);
}

/** Nombres de los checks en falla (no excluidos) de un item: "que le falta". */
export function checksEnFalla(item) {
  const out = [];
  for (const w of item?.warnings || []) {
    if (!w || typeof w !== "object") continue;
    if (esVerdadero(w.check_excluded) || esVerdadero(w.user_excluded)) continue;
    if (w.check_passed === false || String(w.check_passed).toLowerCase() === "false") {
      const nombre = String(w.check_name ?? "").trim();
      if (nombre) out.push(nombre);
    }
  }
  return out;
}

/**
 * Todos los numeros del reporte, calculados una sola vez para que el
 * dashboard, el HTML y (despues) el Excel muestren exactamente lo mismo.
 */
export function resumirBpa(data) {
  const filas = cargarChecks(data);
  const info = data.information || {};
  const panorama = esPanorama(data);

  const noExcl = filas.filter((r) => !r.excluido);
  const cumple = noExcl.filter((r) => r.estado === "Cumple").length;
  const falla = noExcl.filter((r) => r.estado === "Falla").length;
  const noAplica = noExcl.filter((r) => r.estado === "No aplica").length;
  const excluidos = filas.length - noExcl.length;
  const aplicables = cumple + falla;

  const fallasPorSev = Object.fromEntries(SEVERIDADES.map((s) => [s, 0]));
  for (const r of noExcl) {
    if (r.estado === "Falla") fallasPorSev[r.sev] = (fallasPorSev[r.sev] || 0) + 1;
  }

  // Cumplimiento por categoria top-level (device, network, objects, policies...).
  const porCategoria = {};
  for (const r of noExcl) {
    if (r.estado !== "Cumple" && r.estado !== "Falla") continue;
    const e = (porCategoria[r.cat] ||= { aplicables: 0, cumple: 0, falla: 0 });
    e.aplicables++;
    if (r.estado === "Cumple") e.cumple++;
    else e.falla++;
  }
  const categorias = Object.keys(porCategoria).sort().map((cat) => {
    const e = porCategoria[cat];
    return { cat, ...e, pct: e.aplicables ? (e.cumple / e.aplicables) * 100 : 0 };
  });

  // Hallazgos: checks distintos en falla, con cuantos objetos afecta cada uno.
  const agrupados = new Map();
  for (const r of noExcl) {
    if (r.estado !== "Falla") continue;
    let e = agrupados.get(r.id);
    if (!e) {
      e = { id: r.id, name: r.name, sev: r.sev, cat: r.cat, ubicaciones: new Set(), afectados: 0 };
      agrupados.set(r.id, e);
    }
    if (r.origen) e.ubicaciones.add(r.origen);
    e.afectados++;
  }
  const hallazgos = [...agrupados.values()]
    .map((e) => ({ ...e, ubicaciones: [...e.ubicaciones].sort() }))
    .sort((a, b) => (SEVORDEN[a.sev] ?? 9) - (SEVORDEN[b.sev] ?? 9) || b.afectados - a.afectados);

  const adoption = Boolean(data.adoption?.security_rule);
  const adoptionSummary = Boolean(data.adoption_summary?.policies?.security_rule);

  return {
    filas,
    dispositivo: {
      tipo: panorama ? "Panorama" : "Firewall (standalone)",
      panorama,
      plataforma: String(info.platform ?? "").toUpperCase(),
      version: String(info.PanOS_version ?? ""),
      ip: String(info.device_ip_address ?? ""),
      fecha: String(info.last_updated_time ?? "").slice(0, 19),
    },
    etiquetaUbicacion: panorama ? "Device groups" : "Ubicaciones",
    kpis: {
      aplicables,
      cumple,
      falla,
      noAplica,
      excluidos,
      pctCumplimiento: aplicables ? (cumple / aplicables) * 100 : 0,
    },
    fallasPorSev,
    categorias,
    hallazgos,
    faltaAdoption: !(adoption && adoptionSummary),
    // Reporte de la evaluacion local de PAN Helper, no del BPA oficial.
    local: data.information?.origen === "local",
  };
}

// ---------------------------------------------------------------------------
//  Reporte HTML autocontenido
// ---------------------------------------------------------------------------

export function escaparHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

const pct1 = (n) => `${n.toFixed(1)}%`;

function claseSev(sev) {
  if (sev === "Crítico") return "b-crit";
  if (sev === "Advertencia") return "b-warn";
  return "b-info";
}

function claseEstado(estado) {
  if (estado === "Cumple") return "b-ok";
  if (estado === "Falla") return "b-fail";
  return "b-na";
}

function claseFila(estado) {
  if (estado === "Cumple") return "pass-row";
  if (estado === "Falla") return "failed-row";
  return "note-row";
}

/** Fecha local "AAAA-MM-DD HH:MM:SS". */
export function selloLocal(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/**
 * Genera el dashboard HTML (un solo archivo, sin CDN ni fuentes externas).
 *
 * @param {object} resumen   salida de resumirBpa()
 * @param {object} opciones
 * @param {string} opciones.cliente
 * @param {string} [opciones.origen]   texto del subtitulo (p. ej. "Strata Cloud Manager Posture API")
 * @param {string} [opciones.generado] sello de fecha (por defecto, ahora)
 */
export function generarHtmlBpa(resumen, { cliente, origen, generado = selloLocal() } = {}) {
  origen ||= resumen.local
    ? "Evaluación local de PAN Helper (no es el BPA oficial de Palo Alto)"
    : "Strata Cloud Manager Posture API";
  const { dispositivo: d, kpis: k, fallasPorSev, categorias, hallazgos, filas } = resumen;
  const esc = escaparHtml;
  const lblUbic = resumen.etiquetaUbicacion;
  const lblUbicSingular = d.panorama ? "Device group" : "Ubicación";

  const banner = resumen.local
    ? '<div class="banner banner-local"><b>Evaluación local.</b> Estos resultados salen de checks propios de ' +
      "PAN Helper evaluados sobre la configuración, sin enviarla a ningún lado. No sustituyen al Best Practice " +
      "Assessment oficial de Palo Alto, que cubre muchos más controles y datos que no están en el XML.</div>"
    : resumen.faltaAdoption
    ? '<div class="banner">⚠ El reporte no trae las claves <b>adoption</b> / <b>adoption_summary</b> ' +
      "(la API de SCM Posture no siempre las devuelve; no es un error del reporte). Los checks del BPA " +
      "de este reporte no dependen de esas claves y se muestran completos.</div>"
    : "";

  const meta = [
    ["Cliente", cliente],
    ["Tipo", d.tipo],
    ["Plataforma", d.plataforma],
    ["Versión PAN-OS", d.version],
    ["IP del dispositivo", d.ip],
    ["Fecha del análisis", d.fecha],
  ]
    .map(([l, v]) => `<div class="meta-item"><label>${esc(l)}</label><span>${esc(v) || "—"}</span></div>`)
    .join("");

  // Barras por severidad: minimo 15% de alto para que las chicas se vean.
  const maxSev = Math.max(1, ...SEVERIDADES.map((s) => fallasPorSev[s] || 0));
  const colorSev = { "Crítico": "var(--bad)", "Advertencia": "var(--warn)", "Informativo": "var(--info)" };
  const etiquetaSev = { "Crítico": "Crítico", "Advertencia": "Advert.", "Informativo": "Inform." };
  const barras = SEVERIDADES.map((s) => {
    const n = fallasPorSev[s] || 0;
    const alto = n ? Math.max(15, Math.round((100 * n) / maxSev)) : 0;
    return `<div class="bar-col"><div class="bar" style="height:${alto}%;background:${colorSev[s]}">${n}</div>` +
      `<div class="bar-label">${esc(etiquetaSev[s])}</div></div>`;
  }).join("");

  const pctOk = k.pctCumplimiento.toFixed(1);
  const dona = `background:conic-gradient(var(--ok) 0% ${pctOk}%, var(--bad) ${pctOk}% 100%)`;
  // Sin aplicables la dona queda gris en vez de pintarse entera de rojo.
  const donaEstilo = k.aplicables ? dona : "background:var(--border)";

  const filasCategoria = categorias.map((c) => {
    const color = c.pct >= 80 ? "var(--ok)" : "var(--bad)";
    return `<tr><td class="strong">${esc(c.cat)}</td><td class="c">${c.aplicables}</td>` +
      `<td class="c ok">${c.cumple}</td><td class="c bad">${c.falla}</td>` +
      `<td><div class="pbar"><div class="pbar-track"><div class="pbar-fill" style="background:${color};width:${c.pct.toFixed(1)}%"></div></div>` +
      `<span style="color:${color}">${pct1(c.pct)}</span></div></td></tr>`;
  }).join("");

  const filasHallazgos = hallazgos.map((h) =>
    `<tr class="failed-row"><td><span class="badge ${claseSev(h.sev)}">${esc(h.sev)}</span></td>` +
    `<td>${esc(h.name)}</td><td class="c">${esc(h.cat)}</td><td class="c strong">${h.afectados}</td>` +
    `<td>${esc(h.ubicaciones.length ? h.ubicaciones.join(", ") : "—")}</td></tr>`
  ).join("");

  // Detalle: TODAS las filas por categoria, sin deduplicar.
  const porCat = new Map();
  for (const r of filas) {
    if (!porCat.has(r.cat)) porCat.set(r.cat, []);
    porCat.get(r.cat).push(r);
  }
  const secciones = [...porCat.keys()].sort().map((cat) => {
    const lista = porCat.get(cat);
    const cuerpo = lista.map((r) =>
      `<tr class="${claseFila(r.estado)}${r.excluido ? " excl-row" : ""}"><td>${esc(r.sub)}</td><td>${esc(r.origen)}</td>` +
      `<td>${esc(r.objeto)}</td><td><div class="strong">${esc(r.name)}</div>` +
      (r.msg ? `<div class="msg">${esc(r.msg)}</div>` : "") + "</td>" +
      `<td class="c"><span class="badge ${claseSev(r.sev)}">${esc(r.sev)}</span></td>` +
      `<td class="c"><span class="badge ${claseEstado(r.estado)}">${esc(r.estado)}</span>` +
      (r.excluido ? ' <span class="badge b-na">Excluido</span>' : "") + "</td></tr>"
    ).join("");
    return `<div class="section-wrap"><div class="section-head"><span class="section-title">` +
      `${esc(cat)} (${lista.length} checks)</span><button class="section-toggle" type="button">&#9650;</button></div>` +
      `<div class="section-table-wrap"><table><thead><tr><th>Área</th><th>${esc(lblUbicSingular)}</th>` +
      `<th>Objeto</th><th>Check</th><th class="c">Severidad</th><th class="c">Estado</th></tr></thead>` +
      `<tbody>${cuerpo}</tbody></table></div></div>`;
  }).join("");

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Best Practice Assessment — ${esc(cliente)}</title>
<style>
:root{--navy:#123a63;--blue:#1a5fb4;--ok:#1a7d3a;--bad:#b41a1a;--warn:#a86a00;--info:#335a8a;--grey:#667085;--bg:#f6f7f9;--card:#fff;--border:#e3e8f0}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:#1b2430}
.header{background:linear-gradient(135deg,var(--navy),var(--blue));color:#fff;padding:24px 3vw;display:flex;flex-wrap:wrap;align-items:center;gap:16px;justify-content:space-between}
.header h1{font-size:22px;font-weight:800;margin-bottom:4px}
.header p{opacity:.85;font-size:13px}
.toggle-wrapper{display:flex;gap:10px;flex-wrap:wrap}
.toggle-btn{background:rgba(255,255,255,.15);color:#fff;border:1px solid rgba(255,255,255,.5);padding:8px 14px;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer}
.toggle-btn:hover{background:rgba(255,255,255,.28)}
.container{padding:24px 3vw}
.banner{background:#fff6e0;border:1px solid #e8c874;color:#7a5b00;padding:12px 18px;border-radius:8px;font-size:13px;margin-bottom:20px}
.banner-local{background:#eaf2ff;border-color:#a9c6f0;color:#123a63}
.card{background:var(--card);border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:22px;overflow:hidden}
.card-header{padding:14px 22px;border-bottom:1px solid var(--border);font-weight:700;font-size:14px;color:var(--navy)}
.card-body{padding:22px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.meta-item label{font-size:10px;font-weight:700;color:var(--grey);text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:3px}
.meta-item span{font-size:14px;font-weight:700}
.overall-wrap{display:flex;flex-wrap:wrap;gap:28px;align-items:center}
.charts{display:flex;flex-wrap:wrap;gap:34px}
.donut-wrapper,.bar-wrap{display:flex;flex-direction:column;align-items:center;gap:8px}
.donut{width:110px;height:110px;border-radius:50%;display:flex;align-items:center;justify-content:center}
.donut-inner{width:78px;height:78px;background:#fff;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:var(--ok)}
.donut-inner span{font-size:10px;font-weight:400;color:var(--grey)}
.bar-wrap{width:170px}
.bars{display:flex;align-items:flex-end;justify-content:space-around;height:90px;width:100%;border-bottom:2px solid var(--border);padding-bottom:4px;margin-top:8px}
.bar-col{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;width:36px;height:100%}
.bar{width:100%;border-radius:3px 3px 0 0;display:flex;justify-content:center;color:#fff;font-size:10px;padding-top:3px;font-weight:700}
.bar-label{font-size:10px;font-weight:700;color:#495057;margin-top:4px}
.chart-title{font-size:12px;font-weight:700;color:var(--navy)}
.legend{display:flex;gap:10px}
.legend-item{display:flex;align-items:center;gap:5px;font-size:10px;font-weight:600;color:#495057}
.legend-color{width:11px;height:11px;border-radius:3px}
.score-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:14px;flex:1;min-width:260px}
.score-box{text-align:center;padding:16px;border-radius:8px}
.score-box .num{font-size:30px;font-weight:800;line-height:1}
.score-box .lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;margin-top:5px;opacity:.85}
.table-wrap,.section-table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:var(--navy);color:#fff;padding:9px 14px;text-align:left;font-size:11px;font-weight:700}
td{padding:8px 14px;border-bottom:1px solid var(--border);vertical-align:top}
th.c,td.c{text-align:center}
.strong{font-weight:700}
td.ok{color:var(--ok);font-weight:700}
td.bad{color:var(--bad);font-weight:700}
.msg{font-size:11px;color:var(--grey);margin-top:2px}
.pbar{display:flex;align-items:center;gap:8px}
.pbar-track{flex:1;background:var(--border);border-radius:4px;height:8px}
.pbar-fill{height:8px;border-radius:4px}
.pbar span{font-weight:700;font-size:12px;min-width:44px}
tr:hover:not(.failed-row){background:#f8f9fb}
.failed-row{background:#fef2f2;box-shadow:inset 3px 0 0 var(--bad)}
.failed-row:hover{background:#fee2e2}
body.hide-passed .pass-row{display:none}
body.hide-notes .note-row{display:none}
.section-wrap{margin-bottom:16px;background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden}
.section-head{background:linear-gradient(135deg,var(--navy),var(--blue));color:#fff;padding:11px 18px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none}
.section-title{font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:.4px}
.section-toggle{background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.35);color:#fff;padding:2px 9px;border-radius:4px;font-size:13px;cursor:pointer}
.section--collapsed .section-table-wrap{display:none}
.badge{padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700;white-space:nowrap;border:1px solid}
.b-crit,.b-fail{background:#fbe3e3;color:var(--bad)}
.b-warn{background:#fcefdd;color:var(--warn)}
.b-info{background:#eaeff7;color:var(--info)}
.b-ok{background:#e4f3e8;color:var(--ok)}
.b-na{background:#eef1f5;color:var(--grey)}
.subtitle{color:var(--navy);font-size:17px;margin:6px 0 14px}
.vacio{padding:18px 22px;color:var(--grey);font-size:13px}
.footer{padding:16px 3vw;color:#fff;background:var(--navy);font-size:11px;letter-spacing:1px}
@media print{.toggle-wrapper,.section-toggle{display:none}.section--collapsed .section-table-wrap{display:block}}
</style>
</head>
<body>
<div class="header">
<div>
<h1>Best Practice Assessment — ${esc(cliente)}</h1>
<p>${esc(origen)} · Generado ${esc(generado)} · PAN Helper</p>
</div>
<div class="toggle-wrapper">
<button id="togglePassedBtn" class="toggle-btn" type="button">Ocultar Cumple</button>
<button id="toggleNotesBtn" class="toggle-btn" type="button">Ocultar No aplica</button>
</div>
</div>
<div class="container">
${banner}
<div class="card">
<div class="card-header">Información del dispositivo</div>
<div class="card-body"><div class="meta-grid">${meta}</div></div>
</div>
<div class="card">
<div class="card-header">Resumen de cumplimiento</div>
<div class="card-body"><div class="overall-wrap">
<div class="charts">
<div class="donut-wrapper">
<div class="chart-title">Estado general</div>
<div class="donut" style="${donaEstilo}"><div class="donut-inner">${pct1(k.pctCumplimiento)}<span>Cumple</span></div></div>
<div class="legend"><div class="legend-item"><div class="legend-color" style="background:var(--ok)"></div>Cumple</div>
<div class="legend-item"><div class="legend-color" style="background:var(--bad)"></div>Falla</div></div>
</div>
<div class="bar-wrap">
<div class="chart-title">Fallas por severidad</div>
<div class="bars">${barras}</div>
</div>
</div>
<div class="score-grid">
<div class="score-box" style="background:#eaf2ff;color:var(--blue)"><div class="num">${pct1(k.pctCumplimiento)}</div><div class="lbl">% Cumplimiento</div></div>
<div class="score-box" style="background:#eaf7ee;color:var(--ok)"><div class="num">${k.cumple}</div><div class="lbl">Cumple</div></div>
<div class="score-box" style="background:#fdebeb;color:var(--bad)"><div class="num">${k.falla}</div><div class="lbl">Falla</div></div>
<div class="score-box" style="background:#f1f2f5;color:var(--grey)"><div class="num">${k.noAplica}</div><div class="lbl">No aplica</div></div>
<div class="score-box" style="background:#f1f2f5;color:var(--grey)"><div class="num">${k.excluidos}</div><div class="lbl">Excluidos</div></div>
<div class="score-box" style="background:#eaeff7;color:var(--navy)"><div class="num">${k.aplicables}</div><div class="lbl">Aplicables</div></div>
</div>
</div></div>
</div>
<div class="card">
<div class="card-header">Cumplimiento por categoría</div>
${categorias.length
    ? `<div class="table-wrap"><table><thead><tr><th>Categoría</th><th class="c">Aplicables</th><th class="c">Cumple</th><th class="c">Falla</th><th>% Cumplimiento</th></tr></thead><tbody>${filasCategoria}</tbody></table></div>`
    : '<div class="vacio">Sin checks aplicables.</div>'}
</div>
<div class="card">
<div class="card-header">Hallazgos — ${hallazgos.length} checks distintos en falla</div>
${hallazgos.length
    ? `<div class="table-wrap"><table><thead><tr><th>Severidad</th><th>Check</th><th class="c">Categoría</th><th class="c"># Afectados</th><th>${esc(lblUbic)} afectados</th></tr></thead><tbody>${filasHallazgos}</tbody></table></div>`
    : '<div class="vacio">Ningún check en falla.</div>'}
</div>
<h2 class="subtitle">Detalle de configuración por categoría</h2>
${secciones || '<div class="card"><div class="vacio">Sin checks en el reporte.</div></div>'}
</div>
<div class="footer">Generado con PAN Helper</div>
<script>
document.querySelectorAll('.section-head').forEach(function (h) {
  h.addEventListener('click', function () {
    var w = h.parentElement;
    w.classList.toggle('section--collapsed');
    h.querySelector('.section-toggle').innerHTML = w.classList.contains('section--collapsed') ? '&#9660;' : '&#9650;';
  });
});
function alternar(id, clase, mostrar, ocultar) {
  var b = document.getElementById(id);
  b.addEventListener('click', function () {
    document.body.classList.toggle(clase);
    b.textContent = document.body.classList.contains(clase) ? mostrar : ocultar;
  });
}
alternar('togglePassedBtn', 'hide-passed', 'Mostrar Cumple', 'Ocultar Cumple');
alternar('toggleNotesBtn', 'hide-notes', 'Mostrar No aplica', 'Ocultar No aplica');
</script>
</body>
</html>`;
}

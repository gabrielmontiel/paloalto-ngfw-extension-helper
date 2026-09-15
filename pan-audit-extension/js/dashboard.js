// js/dashboard.js
// Shell del dashboard: cablea la UI con los modulos. Al agregar un modulo
// nuevo, este archivo es el unico que lo registra (mismo patron que el
// app.js de PAN-helper v0.1).

import {
  getTargets,
  TARGETS_KEY,
  getHistorialDepuracion,
  agregarSesionDepuracion,
  borrarHistorialDepuracion,
} from "./lib/store.js";
import { setApiLogger, cancelarTodo, sanearValorXpath } from "./lib/panApi.js";
import { reglasDesdeCsv, aCsv, descargarTexto } from "./lib/util.js";
import { ejecutarAuditoria } from "./modules/audit.js";
import { ejecutarBackups } from "./modules/backups.js";
import {
  ejecutarHardening,
  ejecutarHardeningDesdeReporte,
  ejecutarHardeningAutoReporte,
  listarReportesDisponibles,
  comandosSetReporte,
  clonarYAjustar,
} from "./modules/hardening.js";
import {
  depurarObjetos,
  planificarDepuracion,
  aplicarResultadoDepuracion,
  claveObjeto,
} from "./modules/depuracion.js";
import { ejecutarCertificados, ESTADOS } from "./modules/certificados.js";
import {
  procesarJsonBpa,
  procesarScmBpa,
  procesarLocalBpa,
  descargarReporteHtml,
  descargarReporteExcel,
} from "./modules/bestpractices.js";
import { setScmLogger, ORIGENES_SCM } from "./lib/scmApi.js";
import {
  mapearTablaAGrid,
  dividirTabla,
  CAMPOS_GRID,
  csvPlantilla,
  generarApiKeys,
} from "./modules/apikeys.js";

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
//  Consola (de PAN-helper v0.1, con nivel "debug" para el detalle de la API)
// ---------------------------------------------------------------------------

const consola = $("consola");

function log(mensaje, nivel = "info") {
  const linea = document.createElement("div");
  linea.className = `linea ${nivel}`;

  const hora = new Date().toLocaleTimeString("es-CO", { hour12: false });
  const spanHora = document.createElement("span");
  spanHora.className = "hora";
  spanHora.textContent = hora;
  linea.appendChild(spanHora);
  linea.appendChild(document.createTextNode(mensaje));

  consola.appendChild(linea);
  consola.scrollTop = consola.scrollHeight;
}

// Cada llamada a la API de PAN-OS queda registrada aqui como linea "debug".
setApiLogger(log);
setScmLogger(log);

$("btn-limpiar").addEventListener("click", () => {
  consola.textContent = "";
});

$("chk-detalle").addEventListener("change", (e) => {
  consola.classList.toggle("con-detalle", e.target.checked);
  consola.scrollTop = consola.scrollHeight;
});

// Boton rojo global: aborta de inmediato toda llamada al firewall en vuelo
// (fetch y polls de logs). Los modulos terminan con "Operacion cancelada por
// el usuario" y sus botones se rehabilitan en sus propios finally.
$("btn-cancelar").addEventListener("click", () => {
  cancelarTodo();
  log("Cancelacion solicitada: se abortaron las llamadas al firewall en curso.", "warn");
});

// ---------------------------------------------------------------------------
//  Menu lateral desplegable (amplia la zona de trabajo)
// ---------------------------------------------------------------------------

const MENU_KEY = "pan_helper_menu_colapsado";

function aplicarMenu(colapsado) {
  $("layout").classList.toggle("colapsado", colapsado);
  $("btn-menu").innerHTML = colapsado ? "&raquo;" : "&laquo;";
  $("btn-menu").title = colapsado
    ? "Mostrar el menu de modulos"
    : "Ocultar el menu de modulos";
}

$("btn-menu").addEventListener("click", () => {
  const colapsado = !$("layout").classList.contains("colapsado");
  aplicarMenu(colapsado);
  localStorage.setItem(MENU_KEY, colapsado ? "1" : "0");
});

aplicarMenu(localStorage.getItem(MENU_KEY) === "1");

// ---------------------------------------------------------------------------
//  Navegacion entre modulos
// ---------------------------------------------------------------------------

// Enlaces entre modulos (p. ej. de Auditoria a Best Practices).
document.addEventListener("click", (e) => {
  const destino = e.target.closest("[data-ir-modulo]")?.dataset.irModulo;
  if (destino) document.querySelector(`.menu-item[data-modulo="${destino}"]`)?.click();
});

for (const boton of document.querySelectorAll(".menu-item")) {
  boton.addEventListener("click", () => {
    const destino = boton.dataset.modulo;

    for (const b of document.querySelectorAll(".menu-item")) {
      b.classList.toggle("activo", b === boton);
    }
    for (const s of document.querySelectorAll(".modulo")) {
      s.classList.toggle("activo", s.id === `modulo-${destino}`);
    }
  });
}

// ---------------------------------------------------------------------------
//  Conexiones guardadas -> selects y lista de checkboxes
// ---------------------------------------------------------------------------

let targetsCache = [];

async function poblarTargets() {
  targetsCache = await getTargets();

  // Selects de auditoria y hardening (conservan la seleccion si sigue viva).
  for (const selectId of ["a-target", "h-target", "bp-target"]) {
    const select = $(selectId);
    const previo = select.value;
    select.innerHTML = "";

    if (!targetsCache.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "Sin conexiones — agrega una en Conexiones";
      select.appendChild(opt);
      continue;
    }

    for (const t of targetsCache) {
      const opt = document.createElement("option");
      opt.value = t.id;
      opt.textContent = `${t.label} (${t.platform}) — ${t.host}`;
      select.appendChild(opt);
    }
    if (targetsCache.some((t) => t.id === previo)) select.value = previo;
  }

  $("a-btn").disabled = !targetsCache.length;

  // Listas de checkboxes (backups y certificados) — conservan lo marcado.
  for (const id of ["b-targets", "c-targets"]) pintarListaEquipos(id);
}

/** Lista de equipos con checkbox; conserva la seleccion previa si sigue viva. */
function pintarListaEquipos(contenedorId) {
  const lista = $(contenedorId);
  if (!lista) return;

  const marcados = new Set(
    [...lista.querySelectorAll("input:checked")].map((i) => i.value)
  );
  lista.innerHTML = "";

  if (!targetsCache.length) {
    lista.innerHTML =
      '<div class="vacio-checks">Sin conexiones guardadas. ' +
      'Agrega una en <a href="connections.html">Conexiones</a>.</div>';
    return;
  }

  for (const t of targetsCache) {
    const etiqueta = document.createElement("label");
    etiqueta.className = "check";

    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = t.id;
    input.checked = marcados.size ? marcados.has(t.id) : true;

    const texto = document.createElement("span");
    texto.textContent = `${t.label} `;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = `(${t.platform} — ${t.host})`;
    texto.appendChild(meta);

    etiqueta.appendChild(input);
    etiqueta.appendChild(texto);
    lista.appendChild(etiqueta);
  }
}

// Los campos de Panorama dependen de la conexion elegida, asi que se
// reevaluan cada vez que cambia la lista de conexiones.
function poblarTargetsYAjustar() {
  return poblarTargets().then(ajustarFormularioHardening);
}

// Refresco en vivo al agregar/eliminar conexiones desde otra pestana.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[TARGETS_KEY]) poblarTargetsYAjustar();
});

function targetPorId(id) {
  return targetsCache.find((t) => t.id === id) || null;
}

// El formulario de hardening cambia segun la plataforma: un firewall pide
// vsys; un Panorama pide device-group, rulebase (pre/post) y opcionalmente
// los device_name para acotar los logs.
function ajustarFormularioHardening() {
  const target = targetPorId($("h-target").value);
  const esPanorama = /panorama/i.test(target?.platform || "");

  $("h-panorama").classList.toggle("oculto", !esPanorama);
  $("h-campo-vsys").classList.toggle("oculto", esPanorama);

  $("h-plataforma").textContent = !target
    ? ""
    : esPanorama
    ? `Panorama (PAN-OS ${target.swVersion}): las politicas se buscan en un device-group.`
    : `Firewall (PAN-OS ${target.swVersion}): las politicas se buscan en un vsys.`;
}

$("h-target").addEventListener("change", ajustarFormularioHardening);

// ---------------------------------------------------------------------------
//  Modulo: auditoria
// ---------------------------------------------------------------------------

let ultimaAuditoria = null;
let ultimaConfigEl = null;
let ultimaEtiqueta = "";
let ultimoTargetId = null;

// Balance de depuracion del equipo auditado. `conteo` arranca con la
// auditoria y se descuenta con cada sesion; `ultimaSesion` guarda el antes /
// despues de la sesion mas reciente y, si despues se recuenta desde la
// candidate, el valor verificado contra el equipo.
let conteo = null; // { targetId, fuente, totalObjetos }
let ultimaSesion = null;

const SEVERIDAD = { high: "alta", medium: "media", low: "baja", info: "info" };

$("a-btn").addEventListener("click", async () => {
  const target = targetPorId($("a-target").value);
  if (!target) {
    log("No hay conexion seleccionada. Agrega una en Conexiones.", "error");
    return;
  }
  const source = $("a-source").value;

  // Al re-auditar el mismo equipo se conserva lo marcado en "Objetos sin
  // uso": permite recontar entre lotes sin volver a seleccionar.
  const marcadas =
    ultimoTargetId === target.id
      ? new Set(
          [...document.querySelectorAll("#a-panel-unused .d-check:checked")]
            .map((c) => objetosSinUso[Number(c.dataset.idx)])
            .filter(Boolean)
            .map(claveObjeto)
        )
      : new Set();

  $("a-btn").disabled = true;
  $("a-btn").textContent = "Auditando...";
  $("a-resultados").classList.add("oculto");

  try {
    const { configEl, result } = await ejecutarAuditoria(target, source, log);
    ultimaAuditoria = result;
    ultimaConfigEl = configEl;
    ultimaEtiqueta = target.label || target.host;
    ultimoTargetId = target.id;

    const s = result.summary;
    if (ultimaSesion?.targetId !== target.id) {
      ultimaSesion = null;
    } else if (ultimaSesion.porVerificar && source === "candidate") {
      ultimaSesion.verificado = { totalObjetos: s.totalObjectCount, sinUso: s.unusedObjectCount };
      ultimaSesion.porVerificar = false;
      const esperado = ultimaSesion.despues.totalObjetos;
      log(
        `Recuento en la candidate: ${s.totalObjectCount} objeto(s) ` +
          (s.totalObjectCount === esperado
            ? "— coincide con el balance de la sesion."
            : `— el balance esperaba ${esperado}; la diferencia viene de cambios hechos fuera de esta sesion.`),
        s.totalObjectCount === esperado ? "ok" : "warn"
      );
    }
    conteo = { targetId: target.id, fuente: source, totalObjetos: s.totalObjectCount };

    renderAuditoria(result, marcadas);
    $("a-export-json").disabled = false;
    $("a-export-csv").disabled = false;
    $("a-export-xml").disabled = false;
  } catch (e) {
    log(e.message, "error");
  } finally {
    $("a-btn").disabled = false;
    $("a-btn").textContent = "Auditar";
  }
});

export function renderAuditoria(result, marcadas = new Set()) {
  $("a-resultados").classList.remove("oculto");

  renderTarjetasAuditoria(result.summary);

  renderTabla(
    "a-panel-disabled",
    ["Ambito", "Rulebase", "Regla"],
    result.disabledRules.map((r) => [escapeHtml(r.scope), escapeHtml(r.rulebase), escapeHtml(r.name)]),
    "No se encontraron reglas deshabilitadas."
  );

  renderObjetosSinUso(result.unusedObjects, marcadas);
  renderObjetosDuplicados(result.duplicateObjects);
  renderTags(result.tags);

  renderTabla(
    "a-panel-shadowed",
    ["Rulebase", "Regla que tapa", "Regla tapada", "Por que"],
    result.possiblyShadowedRules.map((sh) => [
      escapeHtml(sh.rulebase),
      escapeHtml(sh.shadowingRule),
      escapeHtml(sh.shadowedRule),
      escapeHtml(sh.reason),
    ]),
    "No se encontraron sombras obvias (verificacion heuristica — confirmar siempre a mano)."
  );

  renderTabla(
    "a-panel-bestpractice",
    ["Severidad", "Ambito", "Rulebase", "Regla", "Hallazgo"],
    result.bestPractice.map((b) => [
      `<span class="badge ${b.severity}">${SEVERIDAD[b.severity] || b.severity}</span>`,
      escapeHtml(b.scope),
      escapeHtml(b.rulebase),
      escapeHtml(b.rule),
      escapeHtml(b.issue),
    ]),
    "No se encontraron hallazgos de buenas practicas."
  );
  // Vista rapida por regla; el assessment completo vive en su propio modulo.
  $("a-panel-bestpractice").insertAdjacentHTML(
    "afterbegin",
    '<p class="nota nota-bpa">Vista rapida: cuatro controles sobre las reglas de security. ' +
      "Para el assessment completo (perfiles, zonas, administracion, updates, certificados, " +
      'HA; con HTML y Excel) usa <button type="button" class="secundario" data-ir-modulo="bestpractices">' +
      "Best Practices</button>.</p>"
  );
}

function renderTarjetasAuditoria(s) {
  const tarjetas = [
    ["Reglas auditadas", s.totalRulesAudited],
    ["Objetos en la config", s.totalObjectCount],
    ["Reglas deshabilitadas", s.disabledRuleCount],
    ["Objetos sin uso", s.unusedObjectCount],
    ["Objetos duplicados", s.duplicateObjectCount],
    ["Posibles sombras", s.possiblyShadowedCount],
    ["Buenas practicas", s.bestPracticeFindingCount],
    ["Tags sin uso", `${s.unusedTagCount} / ${s.tagCount}`],
  ];
  $("a-tarjetas").innerHTML = tarjetas
    .map(([lbl, num]) => `<div class="tarjeta"><div class="num">${num}</div><div class="lbl">${escapeHtml(lbl)}</div></div>`)
    .join("");
}

// Pestana "Objetos sin uso": indice por tipo (chips clicables que llevan a
// cada seccion) + una tabla por tipo, cada fila con checkbox para depurar.
// El orden de las secciones es el orden seguro de eliminacion: primero los
// grupos, despues sus miembros.
const ORDEN_SINUSO = ["address-group", "service-group", "address", "service"];

// Objetos sin uso del ultimo analisis, en el mismo indice que los checkbox.
let objetosSinUso = [];

// Maximo de borrados por sesion de "Depurar". Borrar cientos de objetos de
// una vez puede tumbar el firewall (se ha visto con mas de ~200), asi que la
// seleccion se procesa en lotes. Se recuerda entre usos.
const LIMITE_KEY = "pan_helper_depuracion_limite";
const LIMITE_POR_DEFECTO = 100;
const LIMITE_AVISO = 200;

function limiteGuardado() {
  const v = parseInt(localStorage.getItem(LIMITE_KEY), 10);
  return v > 0 ? v : LIMITE_POR_DEFECTO;
}

function limiteSesion() {
  const v = parseInt($("d-limite")?.value, 10);
  return v > 0 ? v : limiteGuardado();
}

function renderObjetosSinUso(objetos, marcadas = new Set()) {
  const panel = $("a-panel-unused");
  objetosSinUso = objetos;

  if (!objetos.length) {
    panel.innerHTML =
      '<div id="d-balance"></div>' +
      '<div class="vacio">No se encontraron objetos address/service sin uso ' +
      "(nota: los grupos dinamicos por tag no se pueden verificar estaticamente).</div>";
    pintarBalance();
    return;
  }

  const porTipo = new Map(ORDEN_SINUSO.map((k) => [k, []]));
  objetos.forEach((o, i) => {
    if (!porTipo.has(o.kind)) porTipo.set(o.kind, []);
    porTipo.get(o.kind).push({ o, i });
  });

  const chips = [];
  const secciones = [];

  for (const [tipo, lista] of porTipo) {
    if (!lista.length) continue;
    const anchor = `sinuso-${tipo}`;

    chips.push(
      `<button type="button" class="chip" data-anchor="${anchor}">` +
        `${escapeHtml(tipo)} <span class="cuenta">${lista.length}</span></button>`
    );

    const filas = lista
      .map(
        ({ o, i }) =>
          `<tr><td><input type="checkbox" class="d-check" data-idx="${i}"` +
          `${marcadas.has(claveObjeto(o)) ? " checked" : ""}></td>` +
          `<td>${escapeHtml(o.scope)}</td><td>${escapeHtml(o.name)}</td><td>` +
          (o.enGrupoSinUso ? '<span class="badge cascada">en grupo sin uso</span> ' : "") +
          `${escapeHtml(o.motivo)}</td></tr>`
      )
      .join("");

    secciones.push(
      `<h4 class="seccion-sinuso" id="${anchor}">${escapeHtml(tipo)} (${lista.length})</h4>` +
        `<table><thead><tr>` +
        `<th><input type="checkbox" class="d-check-tipo" data-tipo="${escapeHtml(tipo)}" ` +
        `title="Seleccionar todos los ${escapeHtml(tipo)}"></th>` +
        `<th>Ambito</th><th>Nombre</th><th>Motivo</th></tr></thead>` +
        `<tbody>${filas}</tbody></table>`
    );
  }

  panel.innerHTML =
    '<div id="d-balance"></div>' +
    `<div class="indice-sinuso">${chips.join("")}</div>` +
    `<p class="nota-sinuso">Se evaluo el uso en todas las politicas (security, NAT, ` +
    `decrypt, QoS, PBF...), en los grupos y en el resto de la configuracion ` +
    `(virtual routers, rutas estaticas, VPN...): lo listado aqui no aparece en ` +
    `ningun otro lado del firewall. Las secciones estan en orden seguro de ` +
    `eliminacion: borrar primero los grupos y despues sus miembros evita ` +
    `errores de referencia.</p>` +
    `<div class="acciones-sinuso">` +
    `<label class="check"><input type="checkbox" id="d-check-todo"> Seleccionar todo</label>` +
    `<label class="campo-limite" title="Cuantos objetos se borran como maximo cada vez que pulsas Depurar. ` +
    `Lo que exceda queda marcado para la siguiente sesion.">` +
    `Max. borrados por sesion <input type="number" id="d-limite" min="1" step="1" value="${limiteGuardado()}"></label>` +
    `<span class="separador"></span>` +
    `<span id="d-seleccion" class="progreso"></span>` +
    `<span id="d-progreso" class="progreso"></span>` +
    `<button type="button" id="d-btn-depurar" class="peligro peligro-grande">Depurar</button>` +
    `</div>` +
    secciones.join("");

  panel.querySelectorAll(".chip[data-anchor]").forEach((chip) => {
    chip.addEventListener("click", () => {
      document
        .getElementById(chip.dataset.anchor)
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  const checks = [...panel.querySelectorAll(".d-check")];

  const refrescar = () => {
    const marcados = checks.filter((c) => c.checked);
    const limite = limiteSesion();
    const lotes = Math.ceil(marcados.length / limite);
    $("d-seleccion").textContent = marcados.length
      ? `${marcados.length} de ${checks.length} objeto(s) seleccionado(s)` +
        (lotes > 1 ? ` — hasta ${limite} por sesion (~${lotes} sesiones)` : "")
      : "";
    $("d-btn-depurar").disabled = marcados.length === 0;
    $("d-limite").classList.toggle("aviso", limite > LIMITE_AVISO);

    const todo = $("d-check-todo");
    todo.checked = marcados.length === checks.length;
    todo.indeterminate = marcados.length > 0 && marcados.length < checks.length;

    // Cada checkbox de seccion refleja el estado de su propio tipo.
    for (const th of panel.querySelectorAll(".d-check-tipo")) {
      const propios = checks.filter((c) => objetosSinUso[Number(c.dataset.idx)].kind === th.dataset.tipo);
      const n = propios.filter((c) => c.checked).length;
      th.checked = n === propios.length;
      th.indeterminate = n > 0 && n < propios.length;
    }
  };

  $("d-check-todo").addEventListener("change", (e) => {
    for (const c of checks) c.checked = e.target.checked;
    refrescar();
  });

  for (const th of panel.querySelectorAll(".d-check-tipo")) {
    th.addEventListener("change", (e) => {
      for (const c of checks) {
        if (objetosSinUso[Number(c.dataset.idx)].kind === th.dataset.tipo) c.checked = e.target.checked;
      }
      refrescar();
    });
  }

  $("d-limite").addEventListener("change", (e) => {
    const v = parseInt(e.target.value, 10);
    if (v > 0) localStorage.setItem(LIMITE_KEY, String(v));
    else e.target.value = limiteGuardado();
    refrescar();
  });

  for (const c of checks) c.addEventListener("change", refrescar);
  $("d-btn-depurar").addEventListener("click", ejecutarDepuracion);

  refrescar();
  pintarBalance();
}

// Borrado de los objetos marcados. Operacion destructiva: se planifica sin
// tocar la red, se muestra exactamente que se va a borrar y que se va a
// omitir, y solo se procede tras confirmacion explicita. Cada sesion borra
// como maximo el limite configurado; lo que sobra queda marcado.
async function ejecutarDepuracion() {
  const target = targetPorId($("a-target").value);
  if (!target) {
    log("No hay conexion seleccionada.", "error");
    return;
  }
  if (target.id !== ultimoTargetId) {
    log(
      "La conexion seleccionada no es la del ultimo analisis. Audita ese equipo antes de depurar.",
      "error"
    );
    return;
  }

  const seleccion = [...document.querySelectorAll("#a-panel-unused .d-check:checked")]
    .map((c) => objetosSinUso[Number(c.dataset.idx)])
    .filter(Boolean);

  if (!seleccion.length) {
    log("Marca al menos un objeto para depurar.", "error");
    return;
  }

  const limite = limiteSesion();
  const { ediciones, aBorrar, bloqueados, pendientes } = planificarDepuracion(seleccion, limite);

  const listado = aBorrar
    .slice(0, 15)
    .map((o) => `  - ${o.kind} '${o.name}' (${o.scope})`)
    .join("\n");
  const resto = aBorrar.length > 15 ? `\n  ...y ${aBorrar.length - 15} mas` : "";

  const avisoLote = pendientes.length
    ? `\n\nSESION LIMITADA a ${limite} borrado(s): quedan ${pendientes.length} objeto(s) ` +
      `marcados para la(s) siguiente(s) sesion(es).`
    : "";

  const avisoLimite =
    aBorrar.length > LIMITE_AVISO
      ? `\n\nCUIDADO: vas a borrar ${aBorrar.length} objetos de una vez. Con mas de ` +
        `${LIMITE_AVISO} se ha visto caer el firewall; considera bajar el maximo por sesion.`
      : "";

  // Grupos que se conservan y a los que primero hay que quitarles miembros.
  const avisoEdiciones = ediciones.length
    ? `\n\nANTES DE BORRAR se quitaran esos objetos de ${ediciones.length} grupo(s) que se ` +
      `conservan:\n` +
      ediciones
        .slice(0, 10)
        .map(
          (e) =>
            `  - ${e.grupo.name}: quita ${e.quitar.join(", ")} (le quedan ${e.restantes.length})`
        )
        .join("\n")
    : "";

  const avisoBloqueados = bloqueados.length
    ? `\n\nSE OMITIRAN ${bloqueados.length} objeto(s) porque quitarlos dejaria vacio un grupo ` +
      `(${bloqueados
        .slice(0, 5)
        .map((b) => `${b.objeto.name} -> ${b.gruposVacios.join(", ")}`)
        .join("; ")}). Marca tambien esos grupos para eliminarlos completos.`
    : "";

  if (!aBorrar.length) {
    log(
      "Ninguno de los objetos seleccionados se puede borrar: quitarlos dejaria vacio " +
        "un grupo estatico, algo que PAN-OS no admite.",
      "error"
    );
    for (const b of bloqueados) {
      log(`${b.objeto.name}: marca tambien el grupo ${b.gruposVacios.join(", ")}.`, "error");
    }
    return;
  }

  const confirmado = confirm(
    `ATENCION: se ELIMINARAN ${aBorrar.length} objeto(s) de la CANDIDATE config de ` +
      `${target.host}:\n\n${listado}${resto}${avisoLote}${avisoLimite}${avisoEdiciones}${avisoBloqueados}\n\n` +
      `Los grupos marcados se borran antes que sus miembros para evitar errores de ` +
      `referencia.\n\n` +
      `NO se hara commit — es obligatorio que revises los cambios en la GUI del firewall ` +
      `antes de confirmarlos. Si algo sale mal, un "revert" en la GUI deshace todo.\n\n` +
      `¿Continuar?`
  );
  if (!confirmado) {
    log("Depuracion cancelada por el usuario antes de empezar.");
    return;
  }

  const btn = $("d-btn-depurar");
  btn.disabled = true;
  btn.textContent = "Depurando...";
  $("d-limite").disabled = true;
  $("d-progreso").textContent = "";

  try {
    const antes = { totalObjetos: conteo.totalObjetos, sinUso: objetosSinUso.length };
    const historial = await getHistorialDepuracion(target.id);

    const r = await depurarObjetos({ target, seleccion, limite }, log, (hechos, total) => {
      $("d-progreso").textContent = `${hechos} / ${total}`;
    });

    const restantes = aplicarResultadoDepuracion(objetosSinUso, r);
    const despues = { totalObjetos: antes.totalObjetos - r.eliminados, sinUso: restantes.length };
    const fecha = new Date().toISOString();

    conteo.totalObjetos = despues.totalObjetos;
    ultimaSesion = {
      targetId: target.id,
      fecha,
      fuente: conteo.fuente,
      antes,
      despues,
      eliminados: r.eliminados,
      desvinculados: r.desvinculados,
      fallidos: r.fallidos,
      omitidos: r.omitidos,
      pendientes: r.pendientes,
      acumuladoAntes: historial.totalEliminados,
      acumuladoDespues: historial.totalEliminados + r.eliminados,
      porVerificar: r.eliminados > 0,
      verificado: null,
    };

    if (r.eliminados || r.desvinculados || r.fallidos) {
      await agregarSesionDepuracion(target.id, {
        fecha,
        fuente: conteo.fuente,
        totalAntes: antes.totalObjetos,
        totalDespues: despues.totalObjetos,
        sinUsoAntes: antes.sinUso,
        sinUsoDespues: despues.sinUso,
        eliminados: r.eliminados,
        desvinculados: r.desvinculados,
        fallidos: r.fallidos,
        omitidos: r.omitidos,
        pendientes: r.pendientes,
        limite,
      });
    }

    log(
      `Balance: ${antes.totalObjetos} -> ${despues.totalObjetos} objeto(s) en la config, ` +
        `${antes.sinUso} -> ${despues.sinUso} sin uso. Depurado en este equipo: ` +
        `${ultimaSesion.acumuladoAntes} antes de la sesion, ${ultimaSesion.acumuladoDespues} despues.`,
      "ok"
    );

    // La lista refleja lo borrado y conserva marcado lo pendiente, para
    // seguir con el siguiente lote.
    const eliminados = new Set(r.eliminadosClaves);
    const marcadas = new Set(seleccion.map(claveObjeto).filter((k) => !eliminados.has(k)));
    ultimaAuditoria.unusedObjects = restantes;
    ultimaAuditoria.summary.unusedObjectCount = restantes.length;
    ultimaAuditoria.summary.totalObjectCount = despues.totalObjetos;
    renderTarjetasAuditoria(ultimaAuditoria.summary);
    renderObjetosSinUso(restantes, marcadas);

    log(
      r.pendientes
        ? `Quedan ${r.pendientes} objeto(s) marcados. Revisa el equipo y pulsa Depurar para el siguiente lote ` +
            `(o "Recontar desde la candidate" para refrescar los datos antes).`
        : "Pulsa \"Recontar desde la candidate\" para verificar el balance contra el equipo.",
      "warn"
    );
  } catch (e) {
    log(e.message, "error");
  } finally {
    // Si la lista se volvio a pintar, estos elementos ya no estan en la pagina.
    if (btn.isConnected) {
      btn.disabled = false;
      btn.textContent = "Depurar";
      $("d-limite").disabled = false;
    }
  }
}

// Balance de depuracion: cuanto se habia depurado en el equipo antes de la
// sesion, cuanto despues, y como quedo la config (objetos totales y sin uso).
// El historial vive en chrome.storage por equipo; los numeros de la sesion,
// en memoria hasta la siguiente auditoria de otro equipo.
async function pintarBalance() {
  const cont = $("d-balance");
  if (!cont || !conteo) return;

  const targetId = conteo.targetId;
  const historial = await getHistorialDepuracion(targetId);
  if (!cont.isConnected || conteo?.targetId !== targetId) return;

  const fmtFecha = (iso) =>
    iso ? new Date(iso).toLocaleString("es-CO", { hour12: false }) : "—";
  const item = (lbl, num, sub = "", clase = "") =>
    `<div class="balance-item ${clase}"><div class="lbl">${escapeHtml(lbl)}</div>` +
    `<div class="num">${num}</div>${sub ? `<div class="sub">${sub}</div>` : ""}</div>`;

  const ses = ultimaSesion?.targetId === targetId ? ultimaSesion : null;
  const items = [];

  if (ses) {
    items.push(
      item("Depurado antes de la sesion", ses.acumuladoAntes, "acumulado en este equipo"),
      item("Eliminados en la sesion", ses.eliminados,
        [
          ses.desvinculados ? `${ses.desvinculados} quitado(s) de grupos` : "",
          ses.fallidos ? `${ses.fallidos} con error` : "",
          ses.omitidos ? `${ses.omitidos} omitido(s)` : "",
          ses.pendientes ? `${ses.pendientes} pendiente(s)` : "",
        ].filter(Boolean).join(" · "), "principal"),
      item("Depurado despues de la sesion", ses.acumuladoDespues,
        `en ${historial.totalSesiones} sesion(es) desde ${fmtFecha(historial.desde)}`),
      item("Objetos en la config", `${ses.antes.totalObjetos} &rarr; ${ses.despues.totalObjetos}`, "antes &rarr; despues"),
      item("Objetos sin uso", `${ses.antes.sinUso} &rarr; ${ses.despues.sinUso}`, "antes &rarr; despues")
    );
  } else {
    items.push(
      item("Depurado antes (historial)", historial.totalEliminados,
        historial.totalSesiones
          ? `en ${historial.totalSesiones} sesion(es) desde ${fmtFecha(historial.desde)}`
          : "sin sesiones registradas"),
      item("Objetos en la config", conteo.totalObjetos, `${conteo.fuente} config`),
      item("Objetos sin uso", objetosSinUso.length, "candidatos a depurar")
    );
  }

  let nota = "";
  if (ses?.verificado) {
    const ok = ses.verificado.totalObjetos === ses.despues.totalObjetos;
    nota =
      `<p class="balance-nota ${ok ? "ok" : "warn"}">Verificado contra la candidate: ` +
      `${ses.verificado.totalObjetos} objeto(s), ${ses.verificado.sinUso} sin uso` +
      (ok ? " — coincide con el balance." : ` — el balance esperaba ${ses.despues.totalObjetos} (hubo cambios fuera de esta sesion).`) +
      `</p>`;
  } else if (ses?.porVerificar) {
    nota =
      '<p class="balance-nota">El "despues" se calcula con lo que respondio el equipo. ' +
      'Para confirmarlo, recuenta desde la candidate config (los borrados no llegan a la running hasta el commit).</p>';
  }

  const filas = [...historial.sesiones]
    .reverse()
    .map(
      (h) =>
        `<tr><td>${escapeHtml(fmtFecha(h.fecha))}</td><td>${h.totalAntes} &rarr; ${h.totalDespues}</td>` +
        `<td>${h.sinUsoAntes} &rarr; ${h.sinUsoDespues}</td><td>${h.eliminados}</td>` +
        `<td>${h.desvinculados}</td><td>${h.fallidos}</td><td>${h.pendientes}</td><td>${h.limite ?? "—"}</td></tr>`
    )
    .join("");

  const tablaHistorial = historial.sesiones.length
    ? `<details class="balance-historial"><summary>Historial de sesiones (${historial.sesiones.length}` +
      (historial.totalSesiones > historial.sesiones.length ? ` mas recientes de ${historial.totalSesiones}` : "") +
      `)</summary><table><thead><tr><th>Fecha</th><th>Objetos</th><th>Sin uso</th><th>Eliminados</th>` +
      `<th>Quitados de grupos</th><th>Errores</th><th>Pendientes</th><th>Limite</th></tr></thead>` +
      `<tbody>${filas}</tbody></table></details>`
    : "";

  cont.innerHTML =
    `<div class="balance-depuracion">` +
    `<div class="balance-cabecera"><strong>Balance de depuracion</strong>` +
    `<span class="separador"></span>` +
    `<button type="button" id="d-btn-recontar" class="secundario" ` +
    `title="Vuelve a auditar la candidate config de este equipo conservando lo marcado">Recontar desde la candidate</button>` +
    (historial.totalSesiones
      ? `<button type="button" id="d-btn-borrar-historial" class="secundario">Borrar historial</button>`
      : "") +
    `</div>` +
    `<div class="balance-grid">${items.join("")}</div>` +
    nota +
    tablaHistorial +
    `</div>`;

  $("d-btn-recontar").addEventListener("click", () => {
    if ($("a-target").value !== targetId) {
      log("Selecciona otra vez la conexion auditada para recontar.", "error");
      return;
    }
    $("a-source").value = "candidate";
    $("a-btn").click();
  });

  $("d-btn-borrar-historial")?.addEventListener("click", async () => {
    if (!confirm("¿Borrar el historial de depuracion de este equipo? No afecta al firewall.")) return;
    await borrarHistorialDepuracion(targetId);
    if (ultimaSesion?.targetId === targetId) ultimaSesion = null;
    log("Historial de depuracion borrado para este equipo.");
    pintarBalance();
  });
}

// Pestana "Tags": solo lectura. Tags sin uso, referenciados sin definir,
// duplicados e inventario con el uso de cada uno.
function renderTags(tags) {
  const panel = $("a-panel-tags");
  if (!tags) {
    panel.innerHTML = '<div class="vacio">Sin datos de tags.</div>';
    return;
  }

  const { definidos, noDefinidos, duplicados, cobertura } = tags;
  const sinUso = definidos.filter((t) => !t.enUso);
  const pct = cobertura.reglasSecurity
    ? Math.round((cobertura.reglasSecurityConTag / cobertura.reglasSecurity) * 100)
    : 0;

  const secciones = [
    {
      anchor: "tags-sinuso",
      titulo: "Sin uso",
      lista: sinUso,
      vacio: "Todos los tags definidos se usan en algun lado.",
      cabeceras: ["Ambito", "Tag", "Comentario"],
      fila: (t) => [escapeHtml(t.scope), escapeHtml(t.name), escapeHtml(t.comments)],
    },
    {
      anchor: "tags-nodefinidos",
      titulo: "Referenciados sin definir",
      lista: noDefinidos,
      vacio: "No hay referencias a tags inexistentes.",
      cabeceras: ["Tag", "Referencias", "Donde", "Nota"],
      fila: (t) => [
        escapeHtml(t.name),
        String(t.referencias),
        t.ejemplos.map(escapeHtml).join("<br>") +
          (t.referencias > t.ejemplos.length ? `<br>...y ${t.referencias - t.ejemplos.length} mas` : ""),
        t.soloEnFiltros
          ? "Solo en filtros dinamicos: puede ser un tag registrado en runtime (User-ID, VM Information Sources)."
          : "Usado en reglas u objetos sin un tag definido en su ambito o en uno superior.",
      ],
    },
    {
      anchor: "tags-duplicados",
      titulo: "Duplicados",
      lista: duplicados,
      vacio: "No hay tags duplicados.",
      cabeceras: ["Criterio", "Tag", "Definiciones (ambito — nombre — uso)"],
      fila: (d) => [
        d.criterio === "nombre" ? "mismo nombre en varios ambitos" : "solo difieren en mayusculas",
        escapeHtml(d.clave),
        d.ocurrencias
          .map(
            (o) =>
              `${escapeHtml(o.scope)} — ${escapeHtml(o.name)} ` +
              (o.enUso ? '<span class="badge uso">en uso</span>' : '<span class="badge sinuso">sin uso</span>')
          )
          .join("<br>"),
      ],
    },
    {
      anchor: "tags-inventario",
      titulo: "Inventario",
      lista: definidos,
      vacio: "No hay tags definidos en la configuracion.",
      cabeceras: ["Ambito", "Tag", "Reglas", "Objetos", "Filtros dinamicos", "Uso"],
      fila: (t) => [
        escapeHtml(t.scope),
        escapeHtml(t.name),
        String(t.reglas),
        String(t.objetos),
        String(t.filtrosDinamicos),
        t.enUso
          ? '<span class="badge uso">en uso</span>' +
            (t.otrasReferencias.length
              ? `<br><span class="nota-campo">fuera de politicas y objetos: ${t.otrasReferencias.map(escapeHtml).join("; ")}</span>`
              : "")
          : '<span class="badge sinuso">sin uso</span>',
      ],
    },
  ];

  const chips = secciones
    .map(
      (sec) =>
        `<button type="button" class="chip" data-anchor="${sec.anchor}">` +
        `${escapeHtml(sec.titulo)} <span class="cuenta">${sec.lista.length}</span></button>`
    )
    .join("");

  const html = secciones
    .map((sec) => {
      const cuerpo = sec.lista.length
        ? `<table><thead><tr>${sec.cabeceras.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>` +
          `<tbody>${sec.lista.map((x) => `<tr>${sec.fila(x).map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`
        : `<div class="vacio">${escapeHtml(sec.vacio)}</div>`;
      return `<h4 class="seccion-sinuso" id="${sec.anchor}">${escapeHtml(sec.titulo)} (${sec.lista.length})</h4>${cuerpo}`;
    })
    .join("");

  panel.innerHTML =
    `<div class="indice-sinuso">${chips}</div>` +
    `<p class="nota-sinuso">Uso evaluado en reglas de todas las politicas (tag y group-tag), en ` +
    `objetos address/service y sus grupos, en los filtros de address-groups dinamicos y, ` +
    `como red de seguridad, en el resto de la configuracion. Cobertura: ` +
    `<strong>${cobertura.reglasSecurityConTag} de ${cobertura.reglasSecurity}</strong> regla(s) de ` +
    `security (${pct}%) llevan al menos un tag. Esta pestana es de solo lectura.</p>` +
    html;

  panel.querySelectorAll(".chip[data-anchor]").forEach((chip) => {
    chip.addEventListener("click", () => {
      document
        .getElementById(chip.dataset.anchor)
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

// Pestana "Objetos duplicados": mismo patron de indice + secciones que
// "Objetos sin uso", agrupado por criterio y tipo.
//  - valor:  objetos distintos con el mismo contenido (misma IP/red/FQDN o
//            mismo protocolo/puerto) — candidatos a consolidarse en uno.
//  - nombre: el mismo nombre definido en varios ambitos — el mas cercano
//            tapa al heredado.
// Cada objeto lleva su insignia "en uso" / "sin uso" (misma evaluacion que
// la pestana de objetos sin uso) para decidir cual duplicado se depura.
function renderObjetosDuplicados(duplicados) {
  const panel = $("a-panel-duplicated");

  if (!duplicados.length) {
    panel.innerHTML = '<div class="vacio">No se encontraron objetos duplicados por valor ni por nombre.</div>';
    return;
  }

  // Agrupar por criterio + tipo, respetando el orden ya calculado
  // (valor primero, despues nombre; dentro, por tipo).
  const secciones = new Map(); // `${criterio}::${kind}` -> lista
  for (const d of duplicados) {
    const clave = `${d.criterio}::${d.kind}`;
    if (!secciones.has(clave)) secciones.set(clave, []);
    secciones.get(clave).push(d);
  }

  const badgeUso = (o) =>
    o.enUso
      ? '<span class="badge uso">en uso</span>'
      : '<span class="badge sinuso">sin uso</span>';

  const chips = [];
  const html = [];

  for (const [clave, lista] of secciones) {
    const [criterio, kind] = clave.split("::");
    const anchor = `dup-${criterio}-${kind}`;
    const titulo = `por ${criterio}: ${kind}`;

    chips.push(
      `<button type="button" class="chip" data-anchor="${anchor}">` +
        `${escapeHtml(titulo)} <span class="cuenta">${lista.length}</span></button>`
    );

    const filas = lista
      .map((d) => {
        const objetos = d.objetos
          .map((o) => `${escapeHtml(o.scope)} — ${escapeHtml(o.name)} ${badgeUso(o)}`)
          .join("<br>");
        return `<tr><td>${escapeHtml(d.clave)}</td><td>${objetos}</td></tr>`;
      })
      .join("");

    html.push(
      `<h4 class="seccion-sinuso" id="${anchor}">${escapeHtml(titulo)} (${lista.length})</h4>` +
        `<table><thead><tr><th>${criterio === "valor" ? "Valor" : "Nombre"}</th>` +
        `<th>Objetos (ambito — nombre — uso)</th></tr></thead><tbody>${filas}</tbody></table>`
    );
  }

  panel.innerHTML =
    `<div class="indice-sinuso">${chips.join("")}</div>` +
    `<p class="nota-sinuso">"en uso" = el objeto aparece en alguna politica ` +
    `(security, NAT, decrypt, QoS, PBF...), en un grupo en uso o en otra parte ` +
    `de la configuracion; "sin uso" = candidato a depurar.</p>` +
    html.join("");

  panel.querySelectorAll(".chip[data-anchor]").forEach((chip) => {
    chip.addEventListener("click", () => {
      document
        .getElementById(chip.dataset.anchor)
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

function renderTabla(panelId, cabeceras, filas, mensajeVacio) {
  const panel = $(panelId);
  if (!filas.length) {
    panel.innerHTML = `<div class="vacio">${escapeHtml(mensajeVacio)}</div>`;
    return;
  }
  const thead = `<thead><tr>${cabeceras.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>`;
  const tbody = `<tbody>${filas.map((f) => `<tr>${f.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody>`;
  panel.innerHTML = `<table>${thead}${tbody}</table>`;
}

$("a-tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  document.querySelectorAll("#a-tabs .tab").forEach((t) => t.classList.remove("activo"));
  document.querySelectorAll("#modulo-auditoria .panel").forEach((p) => p.classList.add("oculto"));
  btn.classList.add("activo");
  $(`a-panel-${btn.dataset.tab}`).classList.remove("oculto");
});

// --- exportaciones (a Descargas/PAN-Helper/auditoria/) ---

function marcaTiempo() {
  return new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
}

function slug(s) {
  return (s || "equipo").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

function baseExport() {
  return `PAN-Helper/auditoria/${slug(ultimaEtiqueta)}_${marcaTiempo()}`;
}

$("a-export-json").addEventListener("click", async () => {
  try {
    const ruta = `${baseExport()}.json`;
    await descargarTexto(JSON.stringify(ultimaAuditoria, null, 2), ruta, "application/json");
    log(`Hallazgos exportados a Descargas/${ruta}`, "ok");
  } catch (e) {
    log(e.message, "error");
  }
});

$("a-export-csv").addEventListener("click", async () => {
  try {
    const filas = [];
    for (const r of ultimaAuditoria.disabledRules) {
      filas.push({ seccion: "regla_deshabilitada", ambito: r.scope, rulebase: r.rulebase, nombre: r.name, detalle: "" });
    }
    for (const o of ultimaAuditoria.unusedObjects) {
      filas.push({ seccion: "objeto_sin_uso", ambito: o.scope, rulebase: o.kind, nombre: o.name, detalle: o.motivo });
    }
    for (const d of ultimaAuditoria.duplicateObjects) {
      filas.push({
        seccion: "objeto_duplicado",
        ambito: `por ${d.criterio}`,
        rulebase: d.kind,
        nombre: d.clave,
        detalle: d.objetos
          .map((o) => `${o.scope} — ${o.name} [${o.enUso ? "en uso" : "sin uso"}]`)
          .join("; "),
      });
    }
    const tags = ultimaAuditoria.tags;
    for (const t of tags?.definidos.filter((x) => !x.enUso) || []) {
      filas.push({ seccion: "tag_sin_uso", ambito: t.scope, rulebase: "tag", nombre: t.name, detalle: t.comments });
    }
    for (const t of tags?.noDefinidos || []) {
      filas.push({
        seccion: "tag_no_definido",
        ambito: "",
        rulebase: "tag",
        nombre: t.name,
        detalle: `${t.referencias} referencia(s): ${t.ejemplos.join("; ")}`,
      });
    }
    for (const d of tags?.duplicados || []) {
      filas.push({
        seccion: "tag_duplicado",
        ambito: d.criterio,
        rulebase: "tag",
        nombre: d.clave,
        detalle: d.ocurrencias.map((o) => `${o.scope} — ${o.name}`).join("; "),
      });
    }
    for (const s of ultimaAuditoria.possiblyShadowedRules) {
      filas.push({ seccion: "posible_sombra", ambito: s.rulebase, rulebase: s.shadowingRule, nombre: s.shadowedRule, detalle: s.reason });
    }
    for (const b of ultimaAuditoria.bestPractice) {
      filas.push({ seccion: "buena_practica", ambito: b.scope, rulebase: b.rulebase, nombre: b.rule, detalle: `[${b.severity}] ${b.issue}` });
    }
    const ruta = `${baseExport()}.csv`;
    await descargarTexto(aCsv(filas), ruta);
    log(`Hallazgos exportados a Descargas/${ruta}`, "ok");
  } catch (e) {
    log(e.message, "error");
  }
});

$("a-export-xml").addEventListener("click", async () => {
  try {
    if (!ultimaConfigEl) return;
    const xml = new XMLSerializer().serializeToString(ultimaConfigEl);
    const ruta = `${baseExport()}.xml`;
    await descargarTexto(xml, ruta, "application/xml");
    log(`Config XML exportada a Descargas/${ruta}`, "ok");
  } catch (e) {
    log(e.message, "error");
  }
});

// ---------------------------------------------------------------------------
//  Modulo: backups
// ---------------------------------------------------------------------------

$("form-backups").addEventListener("submit", async (evento) => {
  evento.preventDefault();

  const seleccionados = [...document.querySelectorAll("#b-targets input:checked")]
    .map((i) => targetPorId(i.value))
    .filter(Boolean);

  if (!seleccionados.length) {
    log("Marca al menos un equipo para respaldar.", "error");
    return;
  }

  const incluirConfig = $("b-config").checked;
  const incluirDeviceState = $("b-devicestate").checked;
  const incluirStatsDump = $("b-statsdump").checked;

  if (!incluirConfig && !incluirDeviceState && !incluirStatsDump) {
    log("Selecciona al menos un artefacto para descargar.", "error");
    return;
  }

  const btn = $("b-btn");
  btn.disabled = true;
  btn.textContent = "Ejecutando...";
  $("b-progreso").textContent = `0 / ${seleccionados.length}`;

  try {
    await ejecutarBackups(
      { targets: seleccionados, incluirConfig, incluirDeviceState, incluirStatsDump },
      log,
      (hechos, total) => {
        $("b-progreso").textContent = `${hechos} / ${total}`;
      }
    );
  } catch (e) {
    log(e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Ejecutar";
  }
});

// ---------------------------------------------------------------------------
//  Modulo: hardening App-ID
// ---------------------------------------------------------------------------

// Al cargar un CSV se vuelca la lista al textarea, no se usa directamente:
// asi queda a la vista y editable antes de ejecutar.
$("h-csv").addEventListener("change", async (evento) => {
  const archivo = evento.target.files?.[0];
  if (!archivo) return;

  try {
    const reglas = reglasDesdeCsv(await archivo.text());

    if (!reglas.length) {
      log(`'${archivo.name}': la columna 'Rule' no tiene valores.`, "warn");
      return;
    }

    $("h-reglas").value = reglas.join("\n");
    log(`'${archivo.name}': ${reglas.length} politica(s) cargadas. Revisalas antes de ejecutar.`, "ok");
  } catch (e) {
    log(`No se pudo leer '${archivo.name}': ${e.message}`, "error");
  } finally {
    // Permite volver a cargar el mismo archivo si el usuario lo corrige.
    evento.target.value = "";
  }
});

$("form-hardening").addEventListener("submit", async (evento) => {
  evento.preventDefault();

  const target = targetPorId($("h-target").value);
  if (!target) {
    log("No hay conexion seleccionada. Agrega una en Conexiones.", "error");
    return;
  }

  // Lista explicita del usuario. Se respeta el orden y se quitan duplicados.
  const reglas = [
    ...new Set(
      $("h-reglas")
        .value.split("\n")
        .map((r) => r.trim())
        .filter(Boolean)
    ),
  ];

  const desdeReporte = $("h-fuente").value === "reporte";
  const modoAuto = desdeReporte && $("h-reporte-modo").value === "auto";

  // La lista de politicas es obligatoria salvo en un caso: reutilizar un
  // reporte existente, cuya propia query ya las acota.
  if (!reglas.length && !(desdeReporte && !modoAuto)) {
    log(
      modoAuto
        ? "Indica las politicas: el reporte se construye filtrando por sus nombres."
        : "Indica al menos una politica a analizar.",
      "error"
    );
    return;
  }
  if (desdeReporte && !modoAuto && !$("h-reporte").value.trim()) {
    log("Indica el nombre del Custom Report a leer.", "error");
    return;
  }

  // Guardar la definicion escribe en la candidate config: se confirma.
  if (modoAuto && $("h-guardar-def").checked) {
    const nombre = $("h-reporte").value.trim() || "PAN-Helper-AppID";
    const ok = confirm(
      `Se guardara la definicion del reporte "${nombre}" en la CANDIDATE config de ` +
        `${target.host}.\n\n` +
        `Es la unica escritura de configuracion que hace la extension, y queda limitada ` +
        `a los Custom Reports: no toca politicas ni objetos.\n\n` +
        `NO se hara commit — para que el reporte quede permanente en Monitor > Manage ` +
        `Custom Reports debes commitear tu mismo en la GUI.\n\n` +
        `Los datos del analisis se obtienen igual aunque no lo guardes.\n\n¿Continuar?`
    );
    if (!ok) {
      log("Guardado del reporte cancelado. Marca/desmarca la casilla y reintenta.");
      return;
    }
  }

  const esPanorama = /panorama/i.test(target.platform || "");

  if (esPanorama && !$("h-devicegroup").value.trim()) {
    log("Indica el device-group: en Panorama las politicas viven dentro de uno.", "error");
    return;
  }

  const ubicacion = {
    vsys: esPanorama ? null : $("h-vsys").value.trim() || null,
    deviceGroup: esPanorama ? $("h-devicegroup").value.trim() : null,
    rulebase: esPanorama ? $("h-rulebase").value : null,
  };

  const btn = $("h-btn");
  btn.disabled = true;
  btn.textContent = "Analizando...";
  $("h-progreso").textContent = "";
  $("h-resultado").innerHTML = "";

  try {
    let resumen;

    const onPaso = (hechos, total) => {
      $("h-progreso").textContent = `paso ${hechos} / ${total}`;
    };

    if (modoAuto) {
      ({ resumen } = await ejecutarHardeningAutoReporte(
        {
          target,
          reglas,
          nombreReporte: $("h-reporte").value.trim() || "PAN-Helper-AppID",
          containerXpath: xpathContenedorReportes(ubicacion.vsys),
          periodo: $("h-reporte-periodo").value || "last-90-calendar-days",
          topn: Number($("h-reporte-topn").value) || 500,
          guardarDefinicion: $("h-guardar-def").checked,
          descargarCsv: $("h-csv-resumen").checked,
        },
        log,
        onPaso
      ));
    } else if (desdeReporte) {
      ({ resumen } = await ejecutarHardeningDesdeReporte(
        {
          target,
          reporte: $("h-reporte").value.trim(),
          containerXpath: xpathContenedorReportes(ubicacion.vsys),
          reglas: reglas.length ? reglas : null,
          periodo: $("h-reporte-periodo").value || null,
          topn: Number($("h-reporte-topn").value) || null,
          descargarCsv: $("h-csv-resumen").checked,
        },
        log,
        onPaso
      ));
    } else {
      ({ resumen } = await ejecutarHardening(
        {
          target,
          reglas,
          dias: Number($("h-dias").value),
          descargarCsv: $("h-csv-resumen").checked,
          ...ubicacion,
          dispositivos: esPanorama
            ? $("h-dispositivos")
                .value.split("\n")
                .map((d) => d.trim())
                .filter(Boolean)
            : null,
        },
        log,
        (hechos, total) => {
          $("h-progreso").textContent = `${hechos} / ${total} reglas`;
        }
      ));
    }

    // "Clonar y ajustar" actua sobre el mismo equipo y ubicacion del
    // analisis, venga de logs o de reporte.
    renderResumenHardening({ target, ...ubicacion, resumen });
  } catch (e) {
    log(e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Analizar";
  }
});

// ---------------------------------------------------------------------------
//  Fuente de datos: logs vs Custom Report
// ---------------------------------------------------------------------------

const NOTA_FUENTE = {
  logs:
    "Recorre los logs crudos en tandas, negando las apps ya vistas. Es " +
    "exhaustivo (no se le escapa ninguna aplicacion) pero lento, y el " +
    "periodo lo limita el retention de logs del equipo.",
  reporte:
    "Reutiliza un Custom Report (trsum) ya creado en el equipo: PAN-OS ya " +
    "tiene los datos agregados, asi que es mucho mas rapido y admite " +
    "periodos largos (90 dias). A cambio, el topn del reporte limita la " +
    "muestra y una app muy minoritaria puede quedar fuera.",
};

/** El contenedor de reportes por vsys depende del vsys indicado arriba. */
function xpathContenedorReportes(vsys) {
  const valor = $("h-reporte-contenedor").value;
  if (valor !== "vsys") return valor;
  // Sin sanear, un vsys con comilla rompe la consulta y permite reescribir
  // la ruta para salirse del subarbol de reports.
  const v = sanearValorXpath(vsys) || "vsys1";
  return `/config/devices/entry/vsys/entry[@name='${v}']/reports`;
}

const NOTA_MODO = {
  auto:
    "La extension arma el reporte filtrando por las politicas que escribas " +
    "arriba, lo ejecuta y lee el resultado. Por defecto no escribe nada en " +
    "el equipo; marca la casilla si ademas quieres guardarlo.",
  existente:
    "Reutiliza un reporte que ya creaste en el equipo (por CLI o GUI). Se " +
    "lee su definicion y se ejecuta ad hoc, sin modificarla.",
};

function ajustarFuenteHardening() {
  const desdeReporte = $("h-fuente").value === "reporte";
  const modoAuto = $("h-reporte-modo").value === "auto";

  $("h-bloque-reporte").classList.toggle("oculto", !desdeReporte);
  $("h-bloque-logs").classList.toggle("oculto", desdeReporte);
  $("h-fuente-nota").textContent = NOTA_FUENTE[$("h-fuente").value] || "";
  $("h-reporte-modo-nota").textContent = NOTA_MODO[$("h-reporte-modo").value] || "";

  // "Listar" y guardar-definicion solo tienen sentido en su modo.
  $("h-btn-listar").classList.toggle("oculto", modoAuto);
  $("h-guardar-def-wrap").classList.toggle("oculto", !modoAuto);
  $("h-guardar-def-nota").classList.toggle("oculto", !modoAuto);
  $("h-btn-comandos").classList.toggle("oculto", modoAuto);

  $("h-reporte").placeholder = modoAuto
    ? "PAN-Helper-AppID (nombre con el que se guardaria)"
    : "nombre del reporte existente";

  // Las politicas solo son opcionales al reutilizar un reporte existente.
  $("h-nota-politicas").textContent =
    desdeReporte && !modoAuto
      ? "Opcional al reutilizar un reporte: si lo dejas vacio se reportan todas " +
        "las politicas que traiga (su propia query ya las acota). Si indicas " +
        "nombres, el resultado se filtra a esos."
      : "Se analizan exactamente las politicas que indiques aqui. El programa " +
        "no lee el rulebase ni elige reglas por su cuenta.";
}

$("h-fuente").addEventListener("change", ajustarFuenteHardening);
$("h-reporte-modo").addEventListener("change", ajustarFuenteHardening);

// Lista los reportes que existen en el equipo, para no adivinar el nombre.
$("h-btn-listar").addEventListener("click", async () => {
  const target = targetPorId($("h-target").value);
  if (!target) {
    log("No hay conexion seleccionada.", "error");
    return;
  }

  const btn = $("h-btn-listar");
  btn.disabled = true;
  try {
    const esPanorama = /panorama/i.test(target.platform || "");
    const xpath = xpathContenedorReportes(esPanorama ? null : $("h-vsys").value.trim());
    log(`Listando Custom Reports en ${xpath}...`);

    const nombres = await listarReportesDisponibles(target, xpath);

    if (!nombres.length) {
      $("h-reporte-nota").textContent = "No hay reportes en ese contenedor.";
      log(
        `Sin Custom Reports en ${xpath}. Crealos con los comandos SET (boton de abajo) ` +
          `o revisa si estan en otro contenedor.`,
        "warn"
      );
      return;
    }

    $("h-reporte-nota").textContent = `Disponibles: ${nombres.join(", ")}`;
    log(`${nombres.length} reporte(s): ${nombres.join(", ")}`, "ok");
    if (!$("h-reporte").value.trim()) $("h-reporte").value = nombres[0];
  } catch (e) {
    log(e.message, "error");
  } finally {
    btn.disabled = false;
  }
});

// Comandos SET para crear el reporte. La extension no los ejecuta: crear un
// reporte es escritura de configuracion y el candado la prohibe.
$("h-btn-comandos").addEventListener("click", () => {
  const area = $("h-comandos");
  const contenedor = $("h-reporte-contenedor").value === "vsys" ? "vsys" : "shared";

  area.value = comandosSetReporte({
    nombre: $("h-reporte").value.trim() || "PAN-Helper-AppID",
    periodo: $("h-reporte-periodo").value || "last-90-calendar-days",
    topn: Number($("h-reporte-topn").value) || 100,
    topm: 25,
    contenedor,
  });
  area.classList.remove("oculto");
  area.select();

  log(
    "Comandos SET generados. Pegalos en una sesion CLI en modo 'configure' y haz commit; " +
      "la extension no puede crear el reporte por ti.",
    "warn"
  );
});

ajustarFuenteHardening();

// Contexto del ultimo analisis (equipo, vsys y resumen con la lista cruda
// de apps por regla), necesario para "Clonar y ajustar".
let ultimoHardening = null;

// Tabla de resultados: checkbox por politica (deshabilitado si no hay apps
// que configurar), "seleccionar todo", sufijo configurable y boton "Clonar
// y ajustar" que solo actua sobre las marcadas. La columna Iteraciones NO
// se muestra (queda en la consola y en el CSV); el usuario no la necesita
// para decidir.
export function renderResumenHardening(contexto) {
  const { resumen } = contexto;
  const cont = $("h-resultado");
  if (!resumen?.length) {
    cont.innerHTML = "";
    ultimoHardening = null;
    return;
  }
  ultimoHardening = contexto;

  const cabeceras = ["Politica", "Total Apps", "Aplicaciones Recomendadas", "Apps Alerta"];
  const clonables = resumen.filter((r) => (r._apps || []).length).length;

  const filas = resumen
    .map((r, i) => {
      const clonable = (r._apps || []).length > 0;
      const check =
        `<input type="checkbox" class="h-check" data-idx="${i}"` +
        (clonable ? "" : " disabled title='Sin aplicaciones que configurar'") +
        ">";
      return `<tr><td>${check}</td>${cabeceras.map((c) => `<td>${escapeHtml(r[c])}</td>`).join("")}</tr>`;
    })
    .join("");

  // "Seleccionar todo" solo alcanza a las politicas clonables: las que no
  // tienen apps que configurar quedan siempre fuera (su checkbox esta
  // deshabilitado). Si ninguna es clonable, tampoco tiene sentido.
  const checkTodo =
    `<input type="checkbox" id="h-check-todo"` +
    (clonables ? "" : " disabled") +
    ` title="Seleccionar todas las politicas con aplicaciones (${clonables} de ${resumen.length})">`;

  cont.innerHTML =
    `<table><thead><tr><th>${checkTodo}</th>` +
    `${cabeceras.map((c) => `<th>${escapeHtml(c)}</th>`).join("")}</tr></thead>` +
    `<tbody>${filas}</tbody></table>` +
    `<div class="clonar-opciones">` +
    `<label for="h-sufijo">Sufijo de la regla nueva</label>` +
    `<input type="text" id="h-sufijo" value="${SUFIJO_POR_DEFECTO}" maxlength="30" ` +
    `title="Se agrega al nombre de la regla original. Por defecto -AppID.">` +
    `<span class="nota-inline" id="h-sufijo-ejemplo"></span>` +
    `</div>` +
    `<p class="nota-clonar">"Clonar y ajustar" crea, para cada politica marcada, una regla ` +
    `clonada de la original con el campo application reemplazado por las apps descubiertas, ` +
    `y la mueve justo antes de la original. Todo queda en la <strong>candidate config</strong>: ` +
    `la extension no puede hacer commit — debes revisar y hacer commit manualmente en la GUI.</p>` +
    `<div class="acciones">` +
    `<button type="button" id="h-btn-clonar" class="primario">Clonar y ajustar</button>` +
    `<span id="h-clonar-seleccion" class="progreso"></span>` +
    `<span id="h-clonar-progreso" class="progreso"></span>` +
    `</div>`;

  const checks = [...cont.querySelectorAll(".h-check:not(:disabled)")];

  const refrescarSeleccion = () => {
    const marcados = checks.filter((c) => c.checked).length;
    $("h-clonar-seleccion").textContent =
      `${marcados} de ${clonables} politica(s) seleccionada(s)` +
      (clonables < resumen.length ? ` — ${resumen.length - clonables} sin apps, no aplica` : "");
    const todo = $("h-check-todo");
    todo.checked = marcados > 0 && marcados === clonables;
    todo.indeterminate = marcados > 0 && marcados < clonables;
  };

  $("h-check-todo").addEventListener("change", (e) => {
    for (const c of checks) c.checked = e.target.checked;
    refrescarSeleccion();
  });
  for (const c of checks) c.addEventListener("change", refrescarSeleccion);

  const refrescarEjemplo = () => {
    const sufijo = sufijoActual();
    const base = resumen[0]?.Politica || "rule-1";
    $("h-sufijo-ejemplo").textContent = `Ejemplo: ${base}${sufijo}`;
  };
  $("h-sufijo").addEventListener("input", refrescarEjemplo);

  refrescarSeleccion();
  refrescarEjemplo();

  $("h-btn-clonar").addEventListener("click", ejecutarClonado);
}

const SUFIJO_POR_DEFECTO = "-AppID";

/** Sufijo indicado por el usuario, saneado; vacio vuelve al de por defecto. */
function sufijoActual() {
  // PAN-OS acepta letras, digitos, espacio, punto, guion y guion bajo en el
  // nombre de una regla; se descarta cualquier otro caracter.
  const bruto = ($("h-sufijo")?.value ?? "").replace(/[^\w .-]/g, "").trim();
  return bruto || SUFIJO_POR_DEFECTO;
}

async function ejecutarClonado() {
  if (!ultimoHardening) return;
  const { target, vsys, deviceGroup, rulebase, resumen } = ultimoHardening;

  const seleccion = [...document.querySelectorAll("#h-resultado .h-check:checked")]
    .map((chk) => resumen[Number(chk.dataset.idx)])
    .filter((r) => r && (r._apps || []).length)
    .map((r) => ({ regla: r.Politica, apps: r._apps }));

  if (!seleccion.length) {
    log("Marca al menos una politica con aplicaciones para clonar.", "error");
    return;
  }

  const sufijo = sufijoActual();
  const esPanorama = /panorama/i.test(target.platform || "");

  const ubicacion = esPanorama
    ? `el ${rulebase === "pre" ? "pre" : "post"}-rulebase del device-group "${deviceGroup}"`
    : `el vsys "${vsys || "vsys1"}"`;

  const confirmado = confirm(
    `Se escribiran ${seleccion.length} regla(s) con sufijo "${sufijo}" en la CANDIDATE config ` +
      `de ${target.host}, en ${ubicacion}, y se moveran antes de su regla original.\n\n` +
      `Ejemplo: ${seleccion[0].regla}${sufijo}\n\n` +
      `Si alguna ya existe, se le agregan solo las aplicaciones nuevas (merge); la regla ` +
      `original nunca se modifica.\n\n` +
      `NO se hara commit — es obligatorio que revises las reglas en la GUI` +
      (esPanorama ? " y hagas commit a Panorama + push al device-group" : " y hagas el commit") +
      ` manualmente.\n\n¿Continuar?`
  );
  if (!confirmado) {
    log("Clonado cancelado por el usuario antes de empezar.");
    return;
  }

  const btn = $("h-btn-clonar");
  btn.disabled = true;
  btn.textContent = "Clonando...";
  $("h-clonar-progreso").textContent = "";

  try {
    await clonarYAjustar(
      { target, vsys, deviceGroup, rulebase, seleccion, sufijo },
      log,
      (hechos, total) => {
        $("h-clonar-progreso").textContent = `${hechos} / ${total}`;
      }
    );
  } catch (e) {
    log(e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Clonar y ajustar";
  }
}

// ---------------------------------------------------------------------------
//  Modulo: generacion masiva de API keys
// ---------------------------------------------------------------------------

// Equipos que se van a procesar, calculados por la vista previa. Se guardan
// aqui para que el submit no tenga que re-parsear ni releer el archivo.
let equiposApiKeys = [];

// --- cuadricula de credenciales -------------------------------------------
//
// La cuadricula es la entrada canonica: se pega desde Excel, se escribe a
// mano o se carga un CSV, y en los tres casos queda editable antes de
// ejecutar. Reemplaza al textarea + vista previa que habia antes: lo que se
// ve es exactamente lo que se va a procesar.

/** Crea una fila de la cuadricula con los valores dados. */
function filaGrid(valores = {}) {
  const tr = document.createElement("tr");

  const num = document.createElement("td");
  num.className = "col-num";
  tr.appendChild(num);

  for (const campo of CAMPOS_GRID) {
    const td = document.createElement("td");
    const input = document.createElement("input");
    input.type = campo === "password" ? "password" : "text";
    input.dataset.campo = campo;
    input.value = valores[campo] || "";
    input.autocomplete = "off";
    td.appendChild(input);
    tr.appendChild(td);
  }

  const accion = document.createElement("td");
  accion.className = "col-accion";
  const quitar = document.createElement("button");
  quitar.type = "button";
  quitar.className = "quitar-fila";
  quitar.title = "Quitar fila";
  quitar.textContent = "×";
  accion.appendChild(quitar);
  tr.appendChild(accion);

  return tr;
}

/** Reemplaza el contenido de la cuadricula; siempre deja una fila vacia al final. */
function pintarGrid(equipos = []) {
  const cuerpo = $("k-grid-body");
  cuerpo.innerHTML = "";
  for (const e of equipos) cuerpo.appendChild(filaGrid(e));
  cuerpo.appendChild(filaGrid());
  renumerarGrid();
  refrescarResumenApiKeys();
}

function renumerarGrid() {
  [...$("k-grid-body").rows].forEach((tr, i) => {
    tr.cells[0].textContent = String(i + 1);
  });
}

/** Lee la cuadricula: equipos completos y cuantas filas quedaron a medias. */
function leerGrid() {
  const equipos = [];
  const vistos = new Set();
  let incompletas = 0;
  let duplicadas = 0;

  for (const tr of $("k-grid-body").rows) {
    const v = {};
    for (const input of tr.querySelectorAll("input")) {
      v[input.dataset.campo] = input.value.trim();
    }
    // Una fila totalmente vacia es la de captura, no un error.
    if (!v.cliente && !v.host && !v.usuario && !v.password) continue;

    if (!v.host || !v.usuario || !v.password) {
      incompletas++;
      continue;
    }
    v.host = v.host.replace(/^https?:\/\//, "").replace(/\/$/, "");

    // Un mismo equipo dos veces solo duplica trabajo y confunde la salida.
    const clave = `${v.host}|${v.usuario}`;
    if (vistos.has(clave)) {
      duplicadas++;
      continue;
    }
    vistos.add(clave);
    equipos.push(v);
  }

  return { equipos, incompletas, duplicadas };
}

function refrescarResumenApiKeys() {
  const { equipos, incompletas, duplicadas } = leerGrid();
  equiposApiKeys = equipos;

  const partes = [];
  if (equipos.length) partes.push(`${equipos.length} equipo(s) listo(s)`);
  if (incompletas) partes.push(`${incompletas} fila(s) incompleta(s)`);
  if (duplicadas) partes.push(`${duplicadas} repetida(s)`);
  $("k-grid-resumen").textContent = partes.join(" · ");
}

// Al escribir en la ultima fila aparece otra, para no tener que pulsar
// "Agregar fila" en cada equipo.
$("k-grid").addEventListener("input", (e) => {
  if (!e.target.matches("input")) return;
  const cuerpo = $("k-grid-body");
  if (e.target.closest("tr") === cuerpo.rows[cuerpo.rows.length - 1]) {
    cuerpo.appendChild(filaGrid());
    renumerarGrid();
  }
  refrescarResumenApiKeys();
});

$("k-grid").addEventListener("click", (e) => {
  if (!e.target.matches(".quitar-fila")) return;
  const cuerpo = $("k-grid-body");
  if (cuerpo.rows.length > 1) e.target.closest("tr").remove();
  if (!cuerpo.rows.length) cuerpo.appendChild(filaGrid());
  renumerarGrid();
  refrescarResumenApiKeys();
});

/**
 * Pegado tipo hoja de calculo.
 *
 * Con cabecera reconocible se reemplaza toda la cuadricula, que es el caso
 * habitual: seleccionar el rango completo en Excel y pegarlo. Sin cabecera se
 * rellena desde la celda enfocada hacia abajo y a la derecha, como haria
 * Excel, para poder pegar una sola columna o corregir un bloque.
 */
$("k-grid").addEventListener("paste", (e) => {
  const texto = e.clipboardData?.getData("text") || "";
  const { filas } = dividirTabla(texto);

  // Un valor suelto se deja al pegado normal del navegador.
  if (filas.length <= 1 && (filas[0] || []).length <= 1) return;

  e.preventDefault();

  const { filas: mapeadas, conCabecera } = mapearTablaAGrid(texto);

  if (conCabecera) {
    // Se cargan TODAS las filas, incompletas incluidas: la cuadricula las
    // muestra para que se corrijan, en vez de descartarlas en silencio.
    pintarGrid(mapeadas);
    log(`Pegado: ${mapeadas.length} fila(s) cargadas en la cuadricula.`, "ok");
    return;
  }

  // --- pegado posicional ---
  const activo = document.activeElement;
  const trActivo = activo?.closest?.("tr");
  const cuerpo = $("k-grid-body");
  const filaInicio = trActivo ? [...cuerpo.rows].indexOf(trActivo) : 0;
  const colInicio = activo?.dataset?.campo ? CAMPOS_GRID.indexOf(activo.dataset.campo) : 0;

  filas.forEach((celdas, i) => {
    const indice = filaInicio + i;
    while (cuerpo.rows.length <= indice) cuerpo.appendChild(filaGrid());
    const inputs = cuerpo.rows[indice].querySelectorAll("input");
    celdas.forEach((valor, j) => {
      const col = colInicio + j;
      if (col < inputs.length) inputs[col].value = valor.trim();
    });
  });

  const ultima = cuerpo.rows[cuerpo.rows.length - 1];
  if ([...ultima.querySelectorAll("input")].some((i) => i.value)) {
    cuerpo.appendChild(filaGrid());
  }
  renumerarGrid();
  refrescarResumenApiKeys();
  log(`Pegado: ${filas.length} fila(s) desde la posicion actual.`, "ok");
});

$("k-btn-fila").addEventListener("click", () => {
  $("k-grid-body").appendChild(filaGrid());
  renumerarGrid();
});

$("k-btn-limpiar").addEventListener("click", () => {
  pintarGrid([]);
  log("Cuadricula vaciada.");
});

// El CSV se vuelca a la cuadricula, no se usa directo: asi queda revisable y
// corregible antes de ejecutar.
$("k-archivo").addEventListener("change", async (evento) => {
  const archivo = evento.target.files?.[0];
  if (!archivo) return;
  try {
    const { filas: mapeadas, conCabecera } = mapearTablaAGrid(await archivo.text());
    pintarGrid(mapeadas);
    log(
      `'${archivo.name}': ${mapeadas.length} fila(s) cargadas ` +
        `(${conCabecera ? "con" : "sin"} cabecera). Revisalas antes de ejecutar.`,
      "ok"
    );
  } catch (e) {
    log(`No se pudo leer '${archivo.name}': ${e.message}`, "error");
  } finally {
    evento.target.value = "";
  }
});

$("k-btn-plantilla").addEventListener("click", async () => {
  try {
    await descargarTexto(csvPlantilla(), "PAN-Helper/plantilla-apikeys.csv");
    log("Plantilla en Descargas/PAN-Helper/plantilla-apikeys.csv", "ok");
  } catch (e) {
    log(e.message, "error");
  }
});

pintarGrid([]);

$("form-apikeys").addEventListener("submit", async (evento) => {
  evento.preventDefault();

  if (!equiposApiKeys.length) {
    log("No hay equipos cargados. Pega las credenciales o carga un archivo.", "error");
    return;
  }

  // Chrome exige gesto de usuario vivo: se piden todos los origenes de una,
  // antes de cualquier await, o la peticion se rechaza.
  let permisoOk;
  try {
    permisoOk = await chrome.permissions.request({
      origins: [...new Set(equiposApiKeys.map((e) => `https://${e.host}/*`))],
    });
  } catch (e) {
    log(`No se pudo solicitar permiso de acceso: ${e.message}`, "error");
    return;
  }
  if (!permisoOk) {
    log("Permiso denegado. Sin acceso a los equipos no se puede continuar.", "error");
    return;
  }

  const btn = $("k-btn");
  btn.disabled = true;
  btn.textContent = "Generando...";
  $("k-progreso").textContent = `0 / ${equiposApiKeys.length}`;
  $("k-resultado").innerHTML = "";

  try {
    const { filas, fallosCertificado } = await generarApiKeys(
      { equipos: equiposApiKeys, descargarCsv: true },
      log,
      (hechos, total) => {
        $("k-progreso").textContent = `${hechos} / ${total}`;
      }
    );
    renderResultadoApiKeys(filas, fallosCertificado);
  } catch (e) {
    log(e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Generar API keys";
    // Las contrasenas no siguen en el DOM despues de la ejecucion.
    pintarGrid([]);
    equiposApiKeys = [];
    refrescarResumenApiKeys();
  }
});

// La API key NO se muestra: va solo al CSV, para poder compartir pantalla o
// tomar captura del resultado sin exponer credenciales.
function renderResultadoApiKeys(filas, fallosCertificado) {
  if (!filas?.length) return;

  const cuerpo = filas
    .map((f) => {
      const ok = f.Estado === "OK";
      return (
        `<tr><td>${escapeHtml(f.Cliente || "-")}</td><td>${escapeHtml(f.IP)}</td>` +
        `<td>${escapeHtml(f.Hostname || "-")}</td><td>${escapeHtml(f.Serial || "-")}</td>` +
        `<td>${escapeHtml(f.Modelo || "-")}</td>` +
        `<td><span class="badge ${ok ? "uso" : "high"}">${escapeHtml(f.Estado)}</span></td></tr>`
      );
    })
    .join("");

  const enlaces = fallosCertificado.length
    ? `<div class="aviso-certificado"><strong>${fallosCertificado.length} equipo(s) ` +
      `sin certificado aceptado.</strong> Abrelos, acepta la advertencia y vuelve a ` +
      `ejecutar:<br>` +
      fallosCertificado
        .map(
          (h) =>
            `<a href="https://${encodeURIComponent(h)}" target="_blank" rel="noopener">${escapeHtml(h)}</a>`
        )
        .join(" &middot; ") +
      `</div>`
    : "";

  $("k-resultado").innerHTML =
    enlaces +
    `<table><thead><tr><th>Cliente</th><th>IP</th><th>Hostname</th><th>Serial</th>` +
    `<th>Modelo</th><th>Estado</th></tr></thead><tbody>${cuerpo}</tbody></table>` +
    `<p class="nota-campo">La API key no se muestra en pantalla: esta en el CSV descargado.</p>`;
}

// ---------------------------------------------------------------------------
//  Modulo: certificados
// ---------------------------------------------------------------------------

const ETIQUETA_ESTADO = {
  vencido: "Vencido",
  critico: "Critico",
  proximo: "Proximo",
  vigente: "Vigente",
  desconocido: "Sin fecha",
};

// Reutiliza las insignias de severidad que ya existen para la auditoria.
const BADGE_ESTADO = {
  vencido: "high",
  critico: "medium",
  proximo: "low",
  vigente: "uso",
  desconocido: "info",
};

$("form-certificados").addEventListener("submit", async (evento) => {
  evento.preventDefault();

  const seleccionados = [...document.querySelectorAll("#c-targets input:checked")]
    .map((i) => targetPorId(i.value))
    .filter(Boolean);

  if (!seleccionados.length) {
    log("Marca al menos un equipo para revisar.", "error");
    return;
  }

  const umbralCritico = Number($("c-critico").value);
  const umbralProximo = Number($("c-proximo").value);

  if (umbralProximo <= umbralCritico) {
    log("El umbral 'proximo' debe ser mayor que el 'critico'.", "error");
    return;
  }

  const btn = $("c-btn");
  btn.disabled = true;
  btn.textContent = "Revisando...";
  $("c-progreso").textContent = `0 / ${seleccionados.length}`;
  $("c-resultado").innerHTML = "";

  try {
    const { filas, resumen, fallidos } = await ejecutarCertificados(
      {
        targets: seleccionados,
        umbralCritico,
        umbralProximo,
        incluirVigentes: $("c-vigentes").checked,
        descargarCsv: $("c-csv").checked,
      },
      log,
      (hechos, total) => {
        $("c-progreso").textContent = `${hechos} / ${total}`;
      }
    );
    renderCertificados(filas, resumen, fallidos);
  } catch (e) {
    log(e.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Revisar certificados";
  }
});

function renderCertificados(filas, resumen, fallidos) {
  const cont = $("c-resultado");

  if (!filas.length) {
    cont.innerHTML =
      '<div class="vacio">No se encontraron certificados con los criterios indicados.</div>';
    return;
  }

  // Tarjetas de resumen, en orden de urgencia.
  const tarjetas = [...ESTADOS, "desconocido"]
    .filter((e) => resumen[e])
    .map(
      (e) =>
        `<div class="tarjeta"><div class="num">${resumen[e]}</div>` +
        `<div class="lbl">${escapeHtml(ETIQUETA_ESTADO[e])}</div></div>`
    )
    .join("");

  const cuerpo = filas
    .map(
      (f) =>
        `<tr><td><span class="badge ${BADGE_ESTADO[f.Estado] || "info"}">` +
        `${escapeHtml(ETIQUETA_ESTADO[f.Estado] || f.Estado)}</span></td>` +
        `<td>${escapeHtml(f["Dias restantes"])}</td>` +
        `<td>${escapeHtml(f.Equipo)}</td>` +
        `<td>${escapeHtml(f.Ambito)}</td>` +
        `<td>${escapeHtml(f.Certificado)}</td>` +
        `<td>${escapeHtml(f.Expira)}</td>` +
        `<td>${escapeHtml(f.Emisor)}</td></tr>`
    )
    .join("");

  const errores = fallidos.length
    ? `<div class="aviso-certificado"><strong>${fallidos.length} equipo(s) no respondieron:</strong> ` +
      fallidos.map((f) => escapeHtml(f.host)).join(", ") +
      `. El detalle esta en el registro.</div>`
    : "";

  cont.innerHTML =
    `<section class="tarjetas">${tarjetas}</section>` +
    errores +
    `<div class="panel"><table><thead><tr>` +
    `<th>Estado</th><th>Dias</th><th>Equipo</th><th>Ambito</th>` +
    `<th>Certificado</th><th>Expira</th><th>Emisor</th>` +
    `</tr></thead><tbody>${cuerpo}</tbody></table></div>`;
}

// ---------------------------------------------------------------------------
//  Modulo: best practices (BPA)
// ---------------------------------------------------------------------------

let ultimoBpa = null;

const BADGE_SEV_BPA = { "Crítico": "high", "Advertencia": "medium", "Informativo": "low" };

const valorRadio = (nombre) => document.querySelector(`input[name="${nombre}"]:checked`)?.value;

let origenBpaAnterior = null;

function ajustarFormularioBpa() {
  const origen = valorRadio("bp-origen");
  // Con JSON la configuracion es opcional y arranca en "No usar"; SCM y local
  // la necesitan, asi que "No usar" vuelve a la conexion guardada.
  if (origen !== origenBpaAnterior) {
    if (origen === "json") document.querySelector('input[name="bp-fuente"][value="ninguna"]').checked = true;
    else if (valorRadio("bp-fuente") === "ninguna") document.querySelector('input[name="bp-fuente"][value="conexion"]').checked = true;
    origenBpaAnterior = origen;
  }
  const fuente = valorRadio("bp-fuente");
  $("bp-campos-json").classList.toggle("oculto", origen !== "json");
  $("bp-campos-scm").classList.toggle("oculto", origen !== "scm");
  $("bp-fuente-ninguna").classList.toggle("oculto", origen !== "json");
  $("bp-config-nota").classList.toggle("oculto", origen !== "json");
  $("bp-config-legend").textContent = origen === "json"
    ? "Configuracion del equipo (opcional)"
    : "Configuracion a evaluar";
  $("bp-fuente-conexion").classList.toggle("oculto", fuente !== "conexion");
  $("bp-fuente-archivo").classList.toggle("oculto", fuente !== "archivo");
  $("bp-btn").textContent = origen === "scm" ? "Generar BPA en SCM" : origen === "local" ? "Evaluar localmente" : "Generar reporte";
}

for (const radio of document.querySelectorAll('input[name="bp-origen"], input[name="bp-fuente"]')) {
  radio.addEventListener("change", ajustarFormularioBpa);
}
ajustarFormularioBpa();

/** Configuracion a evaluar (SCM y local). Devuelve un mensaje o null. */
function errorFuenteConfig() {
  if (valorRadio("bp-fuente") === "conexion" && !targetPorId($("bp-target").value)) return "Elige una conexion guardada.";
  if (valorRadio("bp-fuente") === "archivo" && !$("bp-scm-xml").files[0]) return "Elige el running-config.xml.";
  return null;
}

/** Validaciones del origen SCM que no necesitan red. Devuelve un mensaje o null. */
function errorFormularioScm() {
  if (!$("bp-acepto").checked) return "Confirma que la configuracion se enviara a Palo Alto Networks.";
  if (!$("bp-client-id").value.trim() || !$("bp-client-secret").value) return "Escribe el Client ID y el Client Secret del service account de SCM.";
  const fuente = errorFuenteConfig();
  if (fuente) return fuente;
  if (!$("bp-html").checked && !$("bp-excel").checked && !$("bp-guardar-json").checked) {
    return "Marca al menos una salida (HTML, Excel o JSON); si no, el BPA se generaria para nada.";
  }
  return null;
}

$("form-bpa").addEventListener("submit", async (evento) => {
  evento.preventDefault();
  const origen = valorRadio("bp-origen");

  if (origen === "scm") {
    const error = errorFormularioScm();
    if (error) {
      log(error, "error");
      return;
    }
    // Chrome exige el gesto del usuario vivo: el permiso se pide antes de
    // cualquier otro await, o la peticion se rechaza.
    let permiso = false;
    try {
      permiso = await chrome.permissions.request({ origins: ORIGENES_SCM });
    } catch (e) {
      log(`No se pudo solicitar el permiso de acceso a SCM: ${e.message}`, "error");
      return;
    }
    if (!permiso) {
      log("Permiso denegado: sin acceso a Strata Cloud Manager no se puede generar el BPA.", "error");
      return;
    }
  } else if (origen === "local") {
    const error = errorFuenteConfig() ||
      (!$("bp-html").checked && !$("bp-excel").checked ? "Marca al menos una salida (HTML o Excel)." : null);
    if (error) {
      log(error, "error");
      return;
    }
  } else if (!$("bp-json").files[0]) {
    log("Elige el archivo JSON del BPA.", "error");
    return;
  } else if (valorRadio("bp-fuente") !== "ninguna") {
    const error = errorFuenteConfig();
    if (error) {
      log(error, "error");
      return;
    }
  }

  const btn = $("bp-btn");
  const textoBoton = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Generando...";
  $("bp-resultado").innerHTML = "";
  $("bp-progreso").textContent = "";
  $("bp-btn-html").classList.add("oculto");
  $("bp-btn-excel").classList.add("oculto");

  const salidas = {
    cliente: $("bp-cliente").value,
    descargarHtml: $("bp-html").checked,
    descargarExcel: $("bp-excel").checked,
  };

  try {
    if (origen === "scm") {
      ultimoBpa = await procesarScmBpa(
        {
          ...salidas,
          fuente: valorRadio("bp-fuente"),
          target: targetPorId($("bp-target").value),
          archivoXml: $("bp-scm-xml").files[0],
          tipoEquipo: $("bp-tipo").value,
          modelo: $("bp-modelo").value,
          clientId: $("bp-client-id").value,
          clientSecret: $("bp-client-secret").value,
          borrarAlTerminar: $("bp-borrar").checked,
          guardarJson: $("bp-guardar-json").checked,
        },
        log,
        (texto) => {
          $("bp-progreso").textContent = `SCM ${texto}`;
        }
      );
    } else if (origen === "local") {
      ultimoBpa = await procesarLocalBpa(
        { ...salidas, fuente: valorRadio("bp-fuente"), target: targetPorId($("bp-target").value), archivoXml: $("bp-scm-xml").files[0] },
        log
      );
    } else {
      ultimoBpa = await procesarJsonBpa(
        {
          ...salidas,
          archivo: $("bp-json").files[0],
          fuente: valorRadio("bp-fuente"),
          target: targetPorId($("bp-target").value),
          archivoXml: $("bp-scm-xml").files[0],
        },
        log
      );
    }
    renderBpa(ultimoBpa.resumen);
    $("bp-btn-html").classList.remove("oculto");
    $("bp-btn-excel").classList.remove("oculto");
  } catch (e) {
    ultimoBpa = null;
    log(e.message, "error");
  } finally {
    // El secret no se queda en la pagina mas alla de la ejecucion.
    $("bp-client-secret").value = "";
    $("bp-progreso").textContent = "";
    btn.disabled = false;
    btn.textContent = textoBoton;
  }
});

$("bp-btn-html").addEventListener("click", async () => {
  if (!ultimoBpa) return;
  try {
    await descargarReporteHtml(ultimoBpa, log);
  } catch (e) {
    log(e.message, "error");
  }
});

$("bp-btn-excel").addEventListener("click", async () => {
  if (!ultimoBpa) return;
  const btn = $("bp-btn-excel");
  btn.disabled = true;
  try {
    await descargarReporteExcel(ultimoBpa, log);
  } catch (e) {
    log(e.message, "error");
  } finally {
    btn.disabled = false;
  }
});

// Vista rapida en el dashboard; el detalle completo (cada check) va en el HTML.
function renderBpa(resumen) {
  const { kpis: k, dispositivo: d, categorias, hallazgos } = resumen;

  const tarjeta = (num, lbl, clase = "") =>
    `<div class="tarjeta ${clase}"><div class="num">${escapeHtml(num)}</div>` +
    `<div class="lbl">${escapeHtml(lbl)}</div></div>`;

  const tarjetas =
    tarjeta(`${k.pctCumplimiento.toFixed(1)}%`, "Cumplimiento", "principal") +
    tarjeta(k.cumple, "Cumple", "ok") +
    tarjeta(k.falla, "Falla", "falla") +
    tarjeta(k.noAplica, "No aplica") +
    tarjeta(k.excluidos, "Excluidos") +
    tarjeta(k.aplicables, "Aplicables");

  const aviso = resumen.local
    ? '<div class="aviso-certificado">Evaluacion local: checks propios de PAN Helper sobre la ' +
      "configuracion. No sustituye al BPA oficial de Palo Alto.</div>"
    : resumen.faltaAdoption
    ? '<div class="aviso-certificado">El JSON no trae <code>adoption</code> / ' +
      "<code>adoption_summary</code> (la API no siempre los devuelve). Los checks y " +
      "este resumen no dependen de esas claves.</div>"
    : "";

  const barraPct = (pct) => {
    const color = pct >= 80 ? "var(--ok)" : "var(--error)";
    return `<div class="bp-pct"><div class="pista"><div class="relleno" ` +
      `style="width:${pct.toFixed(1)}%;background:${color}"></div></div>` +
      `<span class="valor" style="color:${color}">${pct.toFixed(1)}%</span></div>`;
  };

  const filasCat = categorias
    .map(
      (c) =>
        `<tr><td>${escapeHtml(c.cat)}</td><td>${c.aplicables}</td><td>${c.cumple}</td>` +
        `<td>${c.falla}</td><td>${barraPct(c.pct)}</td></tr>`
    )
    .join("");

  const filasHallazgos = hallazgos
    .map(
      (h) =>
        `<tr><td><span class="badge ${BADGE_SEV_BPA[h.sev] || "info"}">${escapeHtml(h.sev)}</span></td>` +
        `<td>${escapeHtml(h.name)}</td><td>${escapeHtml(h.cat)}</td><td>${h.afectados}</td>` +
        `<td>${escapeHtml(h.ubicaciones.join(", ") || "—")}</td></tr>`
    )
    .join("");

  $("bp-resultado").innerHTML =
    `<p class="nota" style="margin-top:16px;">${escapeHtml(d.tipo)}` +
    (d.plataforma ? ` · ${escapeHtml(d.plataforma)}` : "") +
    (d.version ? ` · PAN-OS ${escapeHtml(d.version)}` : "") +
    (d.fecha ? ` · analisis ${escapeHtml(d.fecha)}` : "") +
    `</p>` +
    `<section class="tarjetas">${tarjetas}</section>` +
    aviso +
    `<h3 class="bp-titulo-tabla">Cumplimiento por categoria</h3>` +
    (categorias.length
      ? `<div class="panel"><table><thead><tr><th>Categoria</th><th>Aplicables</th>` +
        `<th>Cumple</th><th>Falla</th><th>%</th></tr></thead><tbody>${filasCat}</tbody></table></div>`
      : '<div class="vacio">Sin checks aplicables.</div>') +
    `<h3 class="bp-titulo-tabla">Hallazgos — ${hallazgos.length} checks distintos en falla</h3>` +
    (hallazgos.length
      ? `<div class="panel"><table><thead><tr><th>Severidad</th><th>Check</th><th>Categoria</th>` +
        `<th># Afectados</th><th>${escapeHtml(resumen.etiquetaUbicacion)}</th></tr></thead>` +
        `<tbody>${filasHallazgos}</tbody></table></div>`
      : '<div class="vacio">Ningun check en falla.</div>');
}

// ---------------------------------------------------------------------------

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

await poblarTargetsYAjustar();
log("Listo. Elige un modulo; todos usan las conexiones guardadas (sin credenciales repetidas).");
log(
  "Sin commit: la extension escribe solo en la candidate config y solo cuando lo pides. " +
    "La revision y el commit son siempre manuales.",
  "ok"
);

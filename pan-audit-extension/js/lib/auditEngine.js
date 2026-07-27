// js/lib/auditEngine.js
// Analisis puro de la config XML — sin UI y sin red. Tomado de
// pan-audit-extension con dos cambios de fondo:
//
//  1. SIN Policy Optimizer: se elimino overlyOpenRules y todo el calculo de
//     xpaths para escribir reglas. Este motor solo produce hallazgos.
//
//  2. Objetos sin uso EN CASCADA: si un address no aparece en ninguna regla
//     pero es miembro de un address-group que a su vez esta sin uso, el
//     hallazgo lo dice explicitamente ("miembro del grupo 'X' que tampoco se
//     usa — eliminar primero el grupo"). Sin esto, borrar el address antes
//     que el grupo produce un error de referencia en el firewall. La lista
//     ademas se ordena con los grupos primero, que es el orden seguro de
//     eliminacion.
//
// Modelo de ambitos (igual que en pan-audit-extension)
// ----------------------------------------------------
// Los device-groups de Panorama NO estan anidados fisicamente en el XML:
// son una lista PLANA en /config/devices/entry/device-group/entry, y la
// relacion padre/hijo usada para heredar objetos y reglas esta aparte, en
// /config/readonly/devices/entry/device-group/entry/parent-dg.
//
// Un firewall en modo vsys tiene ambitos: shared, vsys1, vsys2... (plano,
// siempre colgando de shared — los vsys no se anidan).
//
// Un objeto solo es "alcanzable" desde reglas de su propio ambito o de los
// ambitos por debajo en la jerarquia, asi que la deteccion de objetos sin
// uso se hace por device-group / vsys, subiendo la cadena de ancestros
// hasta shared.
//
// Limitaciones conocidas: solo se analiza el rulebase de *security* (no
// NAT/decryption/QoS); los templates de Panorama no se recorren; la
// deteccion de sombras es una heuristica ("posible sombra" = revisar a
// mano, no veredicto). Los address-groups dinamicos (por tag) no se pueden
// resolver estaticamente, asi que sus posibles miembros nunca se marcan
// como sin uso (evita falsos positivos).

import { children, child, memberList, entryName, textOf } from "./xmlUtils.js";

const ANY_KEYWORDS = new Set(["any"]);

// ---------- descubrimiento de ambitos ----------

function buildScopeTree(configEl) {
  const sharedEl = child(configEl, "shared");
  const sharedScope = {
    id: "shared",
    label: "Shared",
    kind: "shared",
    name: null,
    element: sharedEl,
    parent: null,
  };

  const devicesEl = child(configEl, "devices");
  const deviceEntry = devicesEl ? children(devicesEl, "entry")[0] : null;
  const deviceEntryName = deviceEntry ? entryName(deviceEntry) : "localhost.localdomain";

  if (!deviceEntry) return { sharedScope, scopes: [sharedScope], deviceEntryName };

  const vsysParent = child(deviceEntry, "vsys");
  if (vsysParent) {
    // Firewall (modo vsys) — plano, siempre colgando de shared.
    const scopes = children(vsysParent, "entry").map((vsysEl) => ({
      id: `vsys:${entryName(vsysEl)}`,
      label: `vsys "${entryName(vsysEl)}"`,
      kind: "vsys",
      name: entryName(vsysEl),
      element: vsysEl,
      parent: sharedScope,
    }));
    return { sharedScope, scopes: scopes.length ? scopes : [sharedScope], deviceEntryName };
  }

  const dgParent = child(deviceEntry, "device-group");
  if (dgParent) {
    // Panorama — lista plana; el mapa parent-dg viene de /config/readonly.
    const parentMap = readParentDgMap(configEl);
    const dgEntries = children(dgParent, "entry");
    const scopeById = new Map();

    for (const dgEl of dgEntries) {
      const name = entryName(dgEl);
      scopeById.set(name, {
        id: `dg:${name}`,
        label: `device-group "${name}"`,
        kind: "device-group",
        name,
        element: dgEl,
        parent: null, // se enlaza abajo cuando ya existen todos
      });
    }
    for (const dgEl of dgEntries) {
      const name = entryName(dgEl);
      const scope = scopeById.get(name);
      const parentName = parentMap.get(name);
      scope.parent = (parentName && scopeById.get(parentName)) || sharedScope;
    }
    const scopes = Array.from(scopeById.values());
    return { sharedScope, scopes: scopes.length ? scopes : [sharedScope], deviceEntryName };
  }

  return { sharedScope, scopes: [sharedScope], deviceEntryName };
}

function readParentDgMap(configEl) {
  const map = new Map();
  const readonlyEl = child(configEl, "readonly");
  const readonlyDevices = readonlyEl ? child(readonlyEl, "devices") : null;
  const readonlyDeviceEntry = readonlyDevices ? children(readonlyDevices, "entry")[0] : null;
  const readonlyDgParent = readonlyDeviceEntry ? child(readonlyDeviceEntry, "device-group") : null;
  if (!readonlyDgParent) return map; // ausente en este export — todos cuelgan de shared
  for (const dgEl of children(readonlyDgParent, "entry")) {
    const name = entryName(dgEl);
    const parentDg = textOf(child(dgEl, "parent-dg"));
    if (parentDg) map.set(name, parentDg);
  }
  return map;
}

function scopeChain(scope) {
  // propio -> ... -> shared
  const chain = [];
  let s = scope;
  while (s) {
    chain.push(s);
    s = s.parent;
  }
  return chain;
}

// ---------- coleccion de objetos ----------

const KINDS = ["address", "address-group", "service", "service-group"];

const KIND_LABELS = {
  address: "address",
  "address-group": "address-group",
  service: "service",
  "service-group": "service-group",
};

function collectObjectsInScope(scope) {
  const el = scope.element;
  return {
    address: indexEntries(child(el, "address")),
    "address-group": indexEntries(child(el, "address-group")),
    service: indexEntries(child(el, "service")),
    "service-group": indexEntries(child(el, "service-group")),
  };
}

function indexEntries(containerEl) {
  const map = new Map();
  for (const e of children(containerEl, "entry")) {
    map.set(entryName(e), e);
  }
  return map;
}

function lookupObject(chain, objectsByScope, kind, name) {
  for (const scope of chain) {
    const objs = objectsByScope.get(scope.id)[kind];
    if (objs.has(name)) return { scope, entry: objs.get(name) };
  }
  return null;
}

// Miembros estaticos de un grupo. Los address-groups los llevan en
// <static><member>...</member></static>; los service-groups en
// <members><member>...</member></members>. Leer solo <static> (bug heredado
// de pan-audit-extension) hacia que los services miembros de un
// service-group en uso quedaran marcados como sin uso.
function groupMembers(groupEl) {
  return [
    ...memberList(child(groupEl, "static")),
    ...memberList(child(groupEl, "members")),
  ];
}

// Valor(es) de un campo que segun el tipo de politica puede ser una lista
// <member> (security, decrypt, QoS...) o un texto directo (el <service> de
// NAT, translated-address simple...).
function valueList(el) {
  if (!el) return [];
  const members = memberList(el);
  if (members.length) return members;
  const t = textOf(el);
  return t ? [t] : [];
}

// ---------- rulebases ----------

function collectRulebases(scope) {
  // Un vsys de firewall tiene un "rulebase"; un device-group / shared de
  // Panorama tiene "pre-rulebase" y "post-rulebase".
  const out = [];
  const single = child(scope.element, "rulebase");
  if (single) {
    const rules = child(child(single, "security"), "rules");
    if (rules) out.push({ label: `${scope.label} / rulebase`, rules });
  }
  for (const tag of ["pre-rulebase", "post-rulebase"]) {
    const rb = child(scope.element, tag);
    if (rb) {
      const rules = child(child(rb, "security"), "rules");
      if (rules) out.push({ label: `${scope.label} / ${tag}`, rules });
    }
  }
  return out;
}

// ---------- otras politicas que referencian objetos ----------

// Ademas del rulebase de security, estas politicas referencian address /
// address-group / service / service-group. Se evaluan SOLO para marcar
// objetos como usados (las pestanas de reglas deshabilitadas / sombras /
// buenas practicas siguen siendo de security).
const EXTRA_POLICY_TYPES = [
  "nat", "decryption", "qos", "pbf", "authentication",
  "application-override", "dos", "sdwan", "tunnel-inspect",
];

function collectExtraPolicyRules(scope) {
  const containers = [];
  const single = child(scope.element, "rulebase");
  if (single) containers.push(single);
  for (const tag of ["pre-rulebase", "post-rulebase"]) {
    const rb = child(scope.element, tag);
    if (rb) containers.push(rb);
  }

  const out = [];
  for (const cont of containers) {
    for (const tipo of EXTRA_POLICY_TYPES) {
      const rules = child(child(cont, tipo), "rules");
      if (!rules) continue;
      const entries = children(rules, "entry");
      if (entries.length) out.push({ tipo, entries });
    }
  }
  return out;
}

// ---------- indice generico de referencias en TODA la config ----------

// Red de seguridad para "el objeto se usa en otro lado del firewall":
// indexa el texto de cada elemento hoja de la config (virtual routers,
// rutas estaticas, IKE, GlobalProtect, interfaces...) con su ruta. Un
// objeto cuyo nombre aparece aqui NO es candidato a depuracion, aunque
// ninguna politica conocida lo referencie.
//
// Se excluyen las definiciones de objetos (address, address-group, service,
// service-group) porque la pertenencia a grupos se evalua aparte con
// semantica de ambitos, y /config/readonly (metadatos de Panorama).
//
// La comparacion es por nombre exacto, sin semantica de ambitos: si el
// nombre aparece en cualquier lado, TODOS los objetos homonimos se
// consideran en uso. Es deliberadamente conservador — ante la duda, no
// recomendar borrar.
function buildReferenceIndex(configEl, log) {
  const EXCLUIR = new Set(["address", "address-group", "service", "service-group", "readonly"]);
  const index = new Map(); // texto -> [rutas] (max 3 rutas guardadas)

  const walk = (el, ruta) => {
    for (const c of el.children) {
      if (EXCLUIR.has(c.tagName)) continue;
      const name = c.getAttribute ? c.getAttribute("name") : null;
      const seg = name ? `${c.tagName} '${name}'` : c.tagName;
      if (c.children.length === 0) {
        const t = c.textContent.trim();
        if (t) {
          if (!index.has(t)) index.set(t, []);
          const rutas = index.get(t);
          if (rutas.length < 3) rutas.push(ruta.concat(seg).slice(-5).join(" > "));
        }
      } else {
        walk(c, ruta.concat(seg));
      }
    }
  };
  walk(configEl, []);

  log(`Indice de referencias: ${index.size} valores de texto distintos en la config.`, "debug");
  return index;
}

function parseRuleEntry(entryEl) {
  return {
    name: entryName(entryEl),
    disabled: textOf(child(entryEl, "disabled")) === "yes",
    action: textOf(child(entryEl, "action")) || "allow",
    from: memberList(child(entryEl, "from")),
    to: memberList(child(entryEl, "to")),
    source: memberList(child(entryEl, "source")),
    destination: memberList(child(entryEl, "destination")),
    application: memberList(child(entryEl, "application")),
    service: memberList(child(entryEl, "service")),
    category: memberList(child(entryEl, "category")),
    logEnd: textOf(child(entryEl, "log-end")),
    logStart: textOf(child(entryEl, "log-start")),
    hasProfileSetting: !!child(entryEl, "profile-setting"),
    tags: memberList(child(entryEl, "tag")),
    description: textOf(child(entryEl, "description")),
  };
}

// ---------- punto de entrada ----------

/**
 * @param {Element} configEl  elemento <config> (running o candidate)
 * @param {(mensaje: string, nivel?: string) => void} log  opcional; recibe
 *        el detalle del analisis para la consola del dashboard.
 */
export function runAudit(configEl, log = () => {}) {
  const { sharedScope, scopes, deviceEntryName } = buildScopeTree(configEl);

  log(`Ambitos detectados: ${scopes.map((s) => s.label).join(", ") || "ninguno"}.`, "debug");

  const allScopes = new Map();
  allScopes.set(sharedScope.id, sharedScope);
  for (const scope of scopes) {
    for (const s of scopeChain(scope)) allScopes.set(s.id, s);
  }

  const objectsByScope = new Map();
  let totalObjetos = 0;
  for (const scope of allScopes.values()) {
    const objs = collectObjectsInScope(scope);
    objectsByScope.set(scope.id, objs);
    const n = KINDS.reduce((acc, k) => acc + objs[k].size, 0);
    totalObjetos += n;
    if (n) log(`${scope.label}: ${n} objeto(s) address/service.`, "debug");
  }
  log(`Total de objetos indexados: ${totalObjetos}.`, "debug");

  const disabledRules = [];
  const bestPractice = [];
  const usedObjectKeys = new Set(); // `${scope.id}::${kind}::${name}`
  const rulebaseGroups = []; // para deteccion de sombras, por rulebase ordenado

  for (const scope of scopes) {
    const chain = scopeChain(scope);

    // Rulebases visibles para este ambito: el propio (pre/post/rulebase)
    // mas, para device-groups, el pre/post-rulebase de shared (Panorama
    // empuja las reglas shared a la politica efectiva de cada device-group).
    const scopesForRulebases = scope.kind === "device-group" ? [scope, sharedScope] : [scope];

    for (const rbScope of scopesForRulebases) {
      for (const rb of collectRulebases(rbScope)) {
        const ruleEntries = children(rb.rules, "entry").map(parseRuleEntry);
        rulebaseGroups.push({ label: `${scope.label} — ${rb.label}`, rules: ruleEntries });
        log(`${rb.label}: ${ruleEntries.length} regla(s) de seguridad.`, "debug");

        for (const rule of ruleEntries) {
          if (rule.disabled) {
            disabledRules.push({ scope: scope.label, rulebase: rb.label, name: rule.name });
          }

          runBestPracticeChecks(rule, scope, rb, bestPractice);

          // Marca los objetos referenciados como usados, resolviendo la
          // pertenencia a grupos de forma recursiva (un grupo puede
          // referenciar otros grupos/objetos).
          markUsed(rule.source, "address", chain, objectsByScope, usedObjectKeys);
          markUsed(rule.destination, "address", chain, objectsByScope, usedObjectKeys);
          markUsed(rule.service, "service", chain, objectsByScope, usedObjectKeys, /*allowAppDefault*/ true);
        }
      }

      // Otras politicas del mismo ambito (NAT, decrypt, QoS, PBF...): solo
      // marcan uso de objetos, con la misma semantica de ambitos y cascada
      // de grupos que security.
      for (const grupo of collectExtraPolicyRules(rbScope)) {
        for (const entry of grupo.entries) {
          markUsed(valueList(child(entry, "source")), "address", chain, objectsByScope, usedObjectKeys);
          markUsed(valueList(child(entry, "destination")), "address", chain, objectsByScope, usedObjectKeys);
          markUsed(valueList(child(entry, "service")), "service", chain, objectsByScope, usedObjectKeys, true);
          // NAT: direcciones traducidas (source-translation, destination-
          // translation, fallback...), como lista <member> o texto directo.
          for (const ta of entry.querySelectorAll("translated-address")) {
            markUsed(valueList(ta), "address", chain, objectsByScope, usedObjectKeys);
          }
        }
        log(`${rbScope.label}: ${grupo.entries.length} regla(s) de ${grupo.tipo} evaluadas para uso de objetos.`, "debug");
      }
    }
  }

  // Evaluacion de uso: semantica (politicas + grupos) y generica (el nombre
  // aparece en cualquier otra parte de la config: virtual routers, rutas
  // estaticas, IKE, GlobalProtect...).
  const referenceIndex = buildReferenceIndex(configEl, log);
  const memberOf = buildMemberOfMap(allScopes, objectsByScope);
  const esUsado = buildUsageEvaluator(usedObjectKeys, referenceIndex, memberOf);

  const unusedObjects = collectUnusedObjects(allScopes, objectsByScope, esUsado, memberOf, log);
  const duplicateObjects = collectDuplicateObjects(allScopes, objectsByScope, esUsado, log);
  const possiblyShadowedRules = findPossibleShadows(rulebaseGroups);

  return {
    deviceEntryName,
    summary: {
      scopeCount: scopes.length,
      totalRulesAudited: rulebaseGroups.reduce((n, g) => n + g.rules.length, 0),
      disabledRuleCount: disabledRules.length,
      unusedObjectCount: unusedObjects.length,
      duplicateObjectCount: duplicateObjects.length,
      possiblyShadowedCount: possiblyShadowedRules.length,
      bestPracticeFindingCount: bestPractice.length,
    },
    disabledRules,
    unusedObjects,
    duplicateObjects,
    possiblyShadowedRules,
    bestPractice,
  };
}

// ---------- objetos usados ----------

function markUsed(values, kind, chain, objectsByScope, usedSet, allowAppDefault = false) {
  for (const raw of values) {
    if (ANY_KEYWORDS.has(raw)) continue;
    if (allowAppDefault && raw === "application-default") continue;
    resolveAndMark(raw, kind, chain, objectsByScope, usedSet, new Set());
  }
}

function resolveAndMark(name, kind, chain, objectsByScope, usedSet, visiting) {
  if (visiting.has(name)) return; // corta referencias circulares entre grupos
  visiting.add(name);

  const groupKind = kind === "address" ? "address-group" : "service-group";

  let found = lookupObject(chain, objectsByScope, kind, name);
  if (found) {
    usedSet.add(`${found.scope.id}::${kind}::${name}`);
    return;
  }

  found = lookupObject(chain, objectsByScope, groupKind, name);
  if (found) {
    usedSet.add(`${found.scope.id}::${groupKind}::${name}`);
    const members = groupMembers(found.entry);
    for (const m of members) {
      resolveAndMark(m, kind, chain, objectsByScope, usedSet, visiting);
    }
    // Los address-groups dinamicos referencian objetos via filtros de tag,
    // no miembros estaticos — no se pueden resolver estaticamente, asi que
    // se dejan fuera de la consideracion de "sin uso" a proposito.
    return;
  }
  // No encontrado = objeto predefinido (p. ej. servicio built-in) o un
  // typo; no hay nada que marcar y no se reportan objetos predefinidos.
}

// ---------- objetos sin uso (con cascada de grupos) ----------

// Mapa de pertenencia: objKey -> [{groupKey, groupName, groupKind, groupScopeLabel}]
// Los miembros de un grupo se resuelven con la cadena de ambitos del propio
// grupo (igual que se resuelven desde una regla).
function buildMemberOfMap(allScopes, objectsByScope) {
  const memberOf = new Map();

  for (const scope of allScopes.values()) {
    const chain = scopeChain(scope);
    const objs = objectsByScope.get(scope.id);

    for (const groupKind of ["address-group", "service-group"]) {
      const baseKind = groupKind === "address-group" ? "address" : "service";

      for (const [groupName, groupEl] of objs[groupKind]) {
        for (const memberName of groupMembers(groupEl)) {
          // El miembro puede ser un objeto simple u otro grupo.
          let found = lookupObject(chain, objectsByScope, baseKind, memberName);
          let memberKind = baseKind;
          if (!found) {
            found = lookupObject(chain, objectsByScope, groupKind, memberName);
            memberKind = groupKind;
          }
          if (!found) continue; // predefinido o typo

          const memberKey = `${found.scope.id}::${memberKind}::${memberName}`;
          if (!memberOf.has(memberKey)) memberOf.set(memberKey, []);
          memberOf.get(memberKey).push({
            groupKey: `${scope.id}::${groupKind}::${groupName}`,
            groupName,
            groupKind,
            groupScopeLabel: scope.label,
            // El modulo de depuracion necesita ubicar el grupo para editarlo
            // y saber que miembros le quedarian al quitar los borrados.
            groupScopeKind: scope.kind,
            groupScopeName: scope.name,
            groupMembers: groupMembers(groupEl),
          });
        }
      }
    }
  }

  return memberOf;
}

// Devuelve esUsado(key, name): un objeto esta en uso si lo referencia una
// politica (security, NAT, decrypt, QoS, PBF...), si su nombre aparece en
// cualquier otra parte de la config (indice generico), o si pertenece a un
// grupo que a su vez esta en uso (recursivo, con guarda de ciclos).
function buildUsageEvaluator(usedObjectKeys, referenceIndex, memberOf) {
  const memo = new Map();

  function esUsado(key, name) {
    if (memo.has(key)) return memo.get(key);
    memo.set(key, false); // guarda contra ciclos de grupos

    let usado = usedObjectKeys.has(key) || referenceIndex.has(name);
    if (!usado) {
      for (const g of memberOf.get(key) || []) {
        if (esUsado(g.groupKey, g.groupName)) {
          usado = true;
          break;
        }
      }
    }

    memo.set(key, usado);
    return usado;
  }

  return esUsado;
}

// Un objeto sin uso que SI es miembro de grupos solo puede estar aqui si
// todos esos grupos tampoco se usan (si alguno se usara, esUsado lo habria
// marcado). El hallazgo lo dice explicitamente; el orden seguro de
// eliminacion (primero el grupo) se explica una vez en la nota de la
// pestana.
function collectUnusedObjects(allScopes, objectsByScope, esUsado, memberOf, log) {
  const unusedObjects = [];
  const seen = new Set();

  for (const scope of allScopes.values()) {
    const objs = objectsByScope.get(scope.id);
    for (const kind of KINDS) {
      for (const name of objs[kind].keys()) {
        const key = `${scope.id}::${kind}::${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (esUsado(key, name)) continue;

        const grupos = memberOf.get(key) || [];
        let motivo;
        let enGrupoSinUso = false;

        if (grupos.length) {
          enGrupoSinUso = true;
          const nombres = [...new Set(grupos.map((g) => `'${g.groupName}'`))].join(", ");
          const tipoGrupo = grupos[0].groupKind === "address-group" ? "address-group" : "service-group";
          motivo = `Sin uso porque el ${tipoGrupo} ${nombres} al que pertenece tampoco se usa.`;
        } else if (kind === "address-group" || kind === "service-group") {
          motivo = "Grupo sin referencias en politicas ni en el resto de la configuracion.";
        } else {
          motivo = "Sin referencias en politicas, grupos ni en el resto de la configuracion.";
        }

        unusedObjects.push({
          scope: scope.label,
          kind: KIND_LABELS[kind],
          name,
          motivo,
          enGrupoSinUso,
          // Datos estructurados (no se muestran en la tabla): el modulo de
          // depuracion los necesita para apuntar el borrado al ambito
          // correcto y para exigir que el grupo se borre antes que sus
          // miembros.
          scopeKind: scope.kind,
          scopeName: scope.name,
          gruposContenedores: grupos.map((g) => ({
            name: g.groupName,
            kind: g.groupKind,
            scopeLabel: g.groupScopeLabel,
            scopeKind: g.groupScopeKind,
            scopeName: g.groupScopeName,
            miembros: g.groupMembers,
          })),
        });
      }
    }
  }

  // Orden seguro de eliminacion: primero los grupos, despues los miembros.
  const ordenKind = { "address-group": 0, "service-group": 1, address: 2, service: 3 };
  unusedObjects.sort(
    (a, b) =>
      ordenKind[a.kind] - ordenKind[b.kind] ||
      a.scope.localeCompare(b.scope) ||
      a.name.localeCompare(b.name)
  );

  const enCascada = unusedObjects.filter((o) => o.enGrupoSinUso).length;
  if (enCascada) {
    log(
      `${enCascada} objeto(s) sin uso son miembros de grupos que tampoco se usan ` +
        `(eliminar primero el grupo).`,
      "debug"
    );
  }

  return unusedObjects;
}

// ---------- objetos duplicados ----------

// Valor comparable de un address: tipo + contenido (ip-netmask, ip-range,
// fqdn...). Dos addresses con el mismo valor son duplicados aunque tengan
// nombre distinto.
function valorDeAddress(entryEl) {
  for (const tag of ["ip-netmask", "ip-range", "ip-wildcard", "fqdn"]) {
    const v = textOf(child(entryEl, tag));
    if (v) return `${tag}: ${v}`;
  }
  return null;
}

// Valor comparable de un service: protocolo/puerto (+ source-port si existe).
function valorDeService(entryEl) {
  const proto = child(entryEl, "protocol");
  if (!proto) return null;
  for (const p of ["tcp", "udp", "sctp"]) {
    const el = child(proto, p);
    if (el) {
      const port = textOf(child(el, "port"));
      const sport = textOf(child(el, "source-port"));
      return `${p}/${port}${sport ? ` (src ${sport})` : ""}`;
    }
  }
  return null;
}

// Detecta duplicados con dos criterios:
//  - por VALOR: addresses (o services) distintos que apuntan al mismo
//    contenido (misma IP/red/FQDN, mismo protocolo/puerto), en cualquier
//    ambito. Son candidatos a consolidarse en un solo objeto.
//  - por NOMBRE: el mismo nombre definido en varios ambitos (p. ej. en
//    shared y en un device-group). El objeto mas cercano tapa al heredado,
//    lo que suele ser fuente de confusion.
function collectDuplicateObjects(allScopes, objectsByScope, esUsado, log) {
  const porValor = new Map(); // `${kind}::${valor}` -> [{scopeId, scope, name}]
  const porNombre = new Map(); // `${kind}::${name}` -> [{scopeId, scope}]

  for (const scope of allScopes.values()) {
    const objs = objectsByScope.get(scope.id);

    for (const kind of ["address", "service"]) {
      for (const [name, entryEl] of objs[kind]) {
        const valor = kind === "address" ? valorDeAddress(entryEl) : valorDeService(entryEl);
        if (!valor) continue;
        const clave = `${kind}::${valor}`;
        if (!porValor.has(clave)) porValor.set(clave, []);
        porValor.get(clave).push({ scopeId: scope.id, scope: scope.label, name });
      }
    }

    for (const kind of KINDS) {
      for (const name of objs[kind].keys()) {
        const clave = `${kind}::${name}`;
        if (!porNombre.has(clave)) porNombre.set(clave, []);
        porNombre.get(clave).push({ scopeId: scope.id, scope: scope.label });
      }
    }
  }

  const duplicados = [];

  // Cada objeto duplicado lleva su estado de uso (la misma evaluacion que
  // objetos sin uso: politicas + grupos + resto de la config), para decidir
  // cual de los duplicados se puede depurar y cual no.
  for (const [clave, lista] of porValor) {
    if (lista.length < 2) continue;
    const sep = clave.indexOf("::");
    const kind = clave.slice(0, sep);
    duplicados.push({
      criterio: "valor",
      kind,
      clave: clave.slice(sep + 2),
      objetos: lista.map((o) => ({
        scope: o.scope,
        name: o.name,
        enUso: esUsado(`${o.scopeId}::${kind}::${o.name}`, o.name),
      })),
    });
  }

  for (const [clave, lista] of porNombre) {
    if (lista.length < 2) continue;
    const sep = clave.indexOf("::");
    const kind = clave.slice(0, sep);
    const name = clave.slice(sep + 2);
    duplicados.push({
      criterio: "nombre",
      kind,
      clave: name,
      objetos: lista.map((s) => ({
        scope: s.scope,
        name,
        enUso: esUsado(`${s.scopeId}::${kind}::${name}`, name),
      })),
    });
  }

  const ordenCriterio = { valor: 0, nombre: 1 };
  duplicados.sort(
    (a, b) =>
      ordenCriterio[a.criterio] - ordenCriterio[b.criterio] ||
      a.kind.localeCompare(b.kind) ||
      a.clave.localeCompare(b.clave)
  );

  if (duplicados.length) {
    log(
      `${duplicados.filter((d) => d.criterio === "valor").length} duplicado(s) por valor, ` +
        `${duplicados.filter((d) => d.criterio === "nombre").length} por nombre.`,
      "debug"
    );
  }

  return duplicados;
}

// ---------- buenas practicas ----------

function runBestPracticeChecks(rule, scope, rb, findings) {
  if (rule.disabled) return; // no acumular hallazgos sobre reglas deshabilitadas

  const isAny = (arr) => arr.length === 1 && arr[0] === "any";
  const anyFields = ["source", "destination", "application", "service"].filter((f) => isAny(rule[f]));

  if (rule.action === "allow" && anyFields.length > 0) {
    const allFour = anyFields.length === 4;
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: allFour
        ? "Regla allow con any/any/any/any (source, destination, application, service)."
        : `Regla allow con "any" en: ${anyFields.join(", ")}.`,
      severity: allFour ? "high" : "medium",
    });
  }

  if (rule.action === "allow" && !rule.hasProfileSetting) {
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: "Regla allow sin security profile / profile group.",
      severity: "medium",
    });
  }

  if (rule.logEnd === "no") {
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: "Log-end deshabilitado explicitamente.",
      severity: "low",
    });
  }

  if (rule.tags.length === 0) {
    findings.push({
      scope: scope.label,
      rulebase: rb.label,
      rule: rule.name,
      issue: "Sin tags — dificulta rastrear duenio/proposito a escala.",
      severity: "info",
    });
  }
}

// ---------- posibles sombras ----------

// Heuristica: dentro del mismo rulebase ordenado, una regla HABILITADA
// anterior con la misma accion y todos sus campos de match en "any" cubre
// por completo cualquier regla posterior. Sub-reporta a proposito: no
// intenta matematicas de rangos CIDR ni pertenencia a grupos. Tratar cada
// "posible sombra" como algo a verificar a mano, no como veredicto.
function findPossibleShadows(rulebaseGroups) {
  const results = [];
  for (const group of rulebaseGroups) {
    const enabled = group.rules.filter((r) => !r.disabled);
    for (let i = 0; i < enabled.length; i++) {
      const earlier = enabled[i];
      const earlierIsBroad =
        setCovers(earlier.source) &&
        setCovers(earlier.destination) &&
        setCovers(earlier.application) &&
        setCovers(earlier.service);
      if (!earlierIsBroad) continue;
      for (let j = i + 1; j < enabled.length; j++) {
        const later = enabled[j];
        if (later.action === earlier.action) {
          results.push({
            rulebase: group.label,
            shadowingRule: earlier.name,
            shadowedRule: later.name,
            reason:
              `"${earlier.name}" aparece antes con source/destination/application/service ` +
              `todos en "any" y la misma accion ("${earlier.action}") — ` +
              `"${later.name}" puede ser inalcanzable.`,
          });
        }
      }
      // Solo se reporta el conjunto de sombras de la primera regla amplia
      // por rulebase, para no duplicar ruido si hay varias seguidas.
      break;
    }
  }
  return results;

  function setCovers(arr) {
    return arr.length === 1 && arr[0] === "any";
  }
}

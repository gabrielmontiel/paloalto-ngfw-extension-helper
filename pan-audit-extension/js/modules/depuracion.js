// js/modules/depuracion.js
// Modulo: depuracion de objetos sin uso.
//
// Elimina de la CANDIDATE config los objetos que el usuario marco en la
// pestana "Objetos sin uso" de la auditoria. NO HACE COMMIT — no existe esa
// capacidad en la extension (ver panRestApi.js); el usuario revisa los
// cambios en la GUI y hace el commit manualmente.
//
// Resguardos propios de una operacion destructiva:
//
//  1. DESVINCULACION PREVIA. Si un objeto marcado pertenece a un grupo que
//     NO se va a borrar, primero se quita del grupo (PUT) y despues se
//     elimina. Sin eso el firewall rechaza el borrado por referencia.
//
//  2. ORDEN SEGURO. Cuando el grupo tambien esta marcado, no hace falta
//     editarlo: se borra el grupo primero y luego sus miembros. El orden se
//     calcula por dependencias (contenedor antes que contenido), asi que
//     tambien funciona con grupos anidados.
//
//  3. GRUPOS QUE QUEDARIAN VACIOS. PAN-OS no admite un grupo estatico sin
//     miembros. Si quitar lo marcado dejaria el grupo vacio y el grupo no
//     fue marcado, esos objetos se omiten con un mensaje que dice que hay
//     que marcar tambien el grupo. Se detecta antes de tocar la red.
//
//  4. LOTES POR SESION. Borrar cientos de objetos de una vez (con mas de
//     ~200 se ha visto caer el firewall) se evita con un maximo de borrados
//     por sesion. El lote es un PREFIJO del orden por dependencias, asi que
//     nunca incluye un miembro sin el grupo marcado que lo contiene; el resto
//     queda pendiente para la siguiente sesion.

import {
  eliminarObjeto,
  obtenerObjeto,
  actualizarObjeto,
  miembrosDeGrupo,
  grupoConMiembros,
  restVersionFromSw,
} from "../lib/panRestApi.js";

const clave = (o) => `${o.scope}::${o.kind}::${o.name}`;
const claveGrupo = (g) => `${g.scopeLabel}::${g.kind}::${g.name}`;

/**
 * Calcula, sin tocar la red, que se va a editar, que se va a borrar y en
 * que orden. Exportada para poder probarla y para alimentar el popup de
 * advertencia con datos exactos.
 *
 * @param {Array<object>} seleccion  objetos de result.unusedObjects
 * @param {number} [limite]  maximo de objetos a borrar en esta sesion
 * @returns {{ediciones: Array, aBorrar: Array, bloqueados: Array, pendientes: Array}}
 *   aBorrar = lote de esta sesion; pendientes = borrables que quedan para
 *   las siguientes.
 */
export function planificarDepuracion(seleccion, limite = Infinity) {
  const seleccionados = new Set(seleccion.map(clave));

  // --- 1. Ediciones de grupo necesarias (grupos NO marcados) ---
  // grupoKey -> { grupo, quitar: string[], claves: string[], miembros: string[] }
  const ediciones = new Map();

  for (const objeto of seleccion) {
    for (const g of objeto.gruposContenedores || []) {
      if (seleccionados.has(claveGrupo(g))) continue; // se borra el grupo entero
      const gk = claveGrupo(g);
      if (!ediciones.has(gk)) {
        ediciones.set(gk, { grupo: g, quitar: [], claves: [], miembros: g.miembros || [] });
      }
      ediciones.get(gk).quitar.push(objeto.name);
      ediciones.get(gk).claves.push(clave(objeto));
    }
  }

  // --- 2. Descartar ediciones imposibles (dejarian el grupo vacio) ---
  const gruposVacios = new Map(); // grupoKey -> nombre
  for (const [gk, ed] of [...ediciones]) {
    ed.restantes = ed.miembros.filter((m) => !ed.quitar.includes(m));
    if (ed.restantes.length === 0) {
      gruposVacios.set(gk, ed.grupo.name);
      ediciones.delete(gk);
    }
  }

  // --- 3. Separar bloqueados de candidatos ---
  const bloqueados = [];
  const candidatos = [];

  for (const objeto of seleccion) {
    const culpables = (objeto.gruposContenedores || [])
      .filter((g) => gruposVacios.has(claveGrupo(g)))
      .map((g) => `'${g.name}'`);

    if (culpables.length) {
      bloqueados.push({ objeto, gruposVacios: [...new Set(culpables)] });
    } else {
      candidatos.push(objeto);
    }
  }

  // --- 4. Orden de borrado por dependencias: contenedor antes que contenido ---
  const ordenados = ordenarPorDependencias(candidatos, new Set(candidatos.map(clave)));

  // --- 5. Lote de la sesion: prefijo del orden seguro ---
  // Los bloqueos se calcularon con la seleccion completa (paso 2), asi que
  // un lote nunca deja vacio un grupo que la seleccion entera tambien
  // vaciaria. Las ediciones se recortan a los objetos del lote.
  const n = Number.isFinite(limite) && limite > 0 ? Math.floor(limite) : ordenados.length;
  const aBorrar = ordenados.slice(0, n);
  const pendientes = ordenados.slice(n);
  const enLote = new Set(aBorrar.map(clave));

  const edicionesLote = [];
  for (const ed of ediciones.values()) {
    const quitar = ed.quitar.filter((_, i) => enLote.has(ed.claves[i]));
    if (!quitar.length) continue;
    edicionesLote.push({
      grupo: ed.grupo,
      quitar,
      miembros: ed.miembros,
      restantes: ed.miembros.filter((m) => !quitar.includes(m)),
    });
  }

  return { ediciones: edicionesLote, aBorrar, bloqueados, pendientes };
}

/**
 * Refleja el resultado de una sesion sobre la lista de objetos sin uso de la
 * ultima auditoria, para poder seguir con el siguiente lote sin volver a
 * descargar la config: quita los eliminados, descuenta los grupos borrados
 * y los miembros quitados de grupos que se conservan.
 *
 * @param {Array<object>} objetos  result.unusedObjects
 * @param {{eliminadosClaves: string[], quitadosDeGrupos: Array<{grupo: string, nombres: string[]}>}} resultado
 * @returns {Array<object>} lista nueva (los objetos que quedan se copian)
 */
export function aplicarResultadoDepuracion(objetos, resultado) {
  const eliminados = new Set(resultado.eliminadosClaves || []);
  const quitados = new Map((resultado.quitadosDeGrupos || []).map((q) => [q.grupo, q.nombres]));

  return objetos
    .filter((o) => !eliminados.has(clave(o)))
    .map((o) => {
      const grupos = (o.gruposContenedores || [])
        .filter((g) => !eliminados.has(claveGrupo(g)))
        .map((g) => {
          const fuera = quitados.get(claveGrupo(g));
          return fuera ? { ...g, miembros: (g.miembros || []).filter((m) => !fuera.includes(m)) } : g;
        });

      if (grupos.length === (o.gruposContenedores || []).length &&
          grupos.every((g, i) => g === o.gruposContenedores[i])) {
        return o;
      }

      const copia = { ...o, gruposContenedores: grupos, enGrupoSinUso: grupos.length > 0 };
      if (!grupos.length && o.enGrupoSinUso) {
        copia.motivo =
          o.kind === "address-group" || o.kind === "service-group"
            ? "Grupo sin referencias en politicas ni en el resto de la configuracion (su grupo contenedor ya se elimino)."
            : "Sin referencias en politicas, grupos ni en el resto de la configuracion (su grupo ya se elimino).";
      }
      return copia;
    });
}

export { clave as claveObjeto };

/**
 * Ordena de forma que ningun objeto se borre antes que los grupos marcados
 * que lo contienen. Soporta grupos anidados; ante un ciclo (que PAN-OS no
 * deberia permitir) emite el resto tal cual en vez de colgarse.
 */
function ordenarPorDependencias(objetos, clavesEnLote) {
  const pendientes = [...objetos];
  const emitidas = new Set();
  const salida = [];

  while (pendientes.length) {
    // Listo = todos sus contenedores del lote ya fueron emitidos.
    const idx = pendientes.findIndex((o) =>
      (o.gruposContenedores || [])
        .filter((g) => clavesEnLote.has(claveGrupo(g)))
        .every((g) => emitidas.has(claveGrupo(g)))
    );

    if (idx === -1) {
      salida.push(...pendientes); // ciclo: se emite lo que queda
      break;
    }

    const [objeto] = pendientes.splice(idx, 1);
    emitidas.add(clave(objeto));
    salida.push(objeto);
  }

  return salida;
}

/**
 * Ejecuta el plan: primero desvincula (PUT), despues borra (DELETE).
 *
 * @param {{target: object, seleccion: Array<object>, limite?: number}} config
 * @param {(mensaje: string, nivel?: string) => void} log
 * @param {(hechos: number, total: number) => void} onProgreso
 * @returns {{eliminados, fallidos, omitidos, desvinculados, pendientes,
 *            eliminadosClaves: string[], quitadosDeGrupos: Array}}
 */
export async function depurarObjetos(config, log, onProgreso) {
  const { target, seleccion, limite } = config;

  if (!seleccion?.length) {
    throw new Error("No se selecciono ningun objeto para depurar.");
  }

  const version = restVersionFromSw(target.swVersion);
  const { ediciones, aBorrar, bloqueados, pendientes } = planificarDepuracion(seleccion, limite);

  // Detalle para que quien llama actualice su lista y el balance.
  const eliminadosClaves = [];
  const quitadosDeGrupos = [];
  const resultado = (extra) => ({
    omitidos: bloqueados.length,
    pendientes: pendientes.length,
    eliminadosClaves,
    quitadosDeGrupos,
    ...extra,
  });

  log(`Depuracion: REST API ${version} en ${target.host}.`);
  if (pendientes.length) {
    log(
      `Sesion limitada a ${aBorrar.length} borrado(s); ${pendientes.length} objeto(s) ` +
        `quedan pendientes para la siguiente sesion.`,
      "warn"
    );
  }
  log(
    "Los cambios quedan en la CANDIDATE config. NO se hara commit: " +
      "revisalos en la GUI y haz commit manualmente.",
    "warn"
  );

  for (const b of bloqueados) {
    log(
      `${b.objeto.name}: omitido. Quitarlo dejaria vacio el grupo ${b.gruposVacios.join(", ")}, ` +
        `y PAN-OS no admite grupos estaticos sin miembros. Marca tambien ese grupo para ` +
        `eliminarlo completo.`,
      "error"
    );
  }

  if (!aBorrar.length) {
    log("No queda ningun objeto que se pueda eliminar con seguridad.", "warn");
    return resultado({ eliminados: 0, fallidos: 0, desvinculados: 0 });
  }

  // El progreso cubre las dos fases: ediciones + borrados.
  const totalPasos = ediciones.length + aBorrar.length;
  let hechos = 0;
  let desvinculados = 0;
  let fallidos = 0;

  // --- Fase 1: quitar los objetos de los grupos que se conservan ---
  const gruposFallidos = new Set();

  for (const ed of ediciones) {
    const g = ed.grupo;
    const ref = { kind: g.kind, name: g.name, scopeKind: g.scopeKind, scopeName: g.scopeName };
    try {
      log(`${g.name}: quitando ${ed.quitar.join(", ")} del grupo...`, "debug");

      const entry = await obtenerObjeto(target, ref);
      if (!entry) throw new Error(`el grupo no existe en ${g.scopeLabel}.`);

      const actuales = miembrosDeGrupo(entry, g.kind);
      if (actuales === null) {
        throw new Error("el grupo no tiene miembros estaticos (grupo dinamico); no se toca.");
      }

      const restantes = actuales.filter((m) => !ed.quitar.includes(m));
      if (restantes.length === actuales.length) {
        log(`${g.name}: ya no contiene los objetos marcados; no se modifica.`, "debug");
      } else if (restantes.length === 0) {
        // La config del equipo difiere de la auditoria (alguien la cambio).
        throw new Error(
          "quitarlos dejaria el grupo vacio segun la configuracion actual del equipo. " +
            "Vuelve a auditar y marca tambien el grupo."
        );
      } else {
        await actualizarObjeto(target, ref, grupoConMiembros(entry, g.kind, restantes));
        log(`${g.name}: ${ed.quitar.length} miembro(s) quitado(s), quedan ${restantes.length}.`, "ok");
        desvinculados += ed.quitar.length;
        quitadosDeGrupos.push({ grupo: claveGrupo(g), nombres: [...ed.quitar] });
      }
    } catch (e) {
      fallidos++;
      gruposFallidos.add(claveGrupo(g));
      log(`${g.name}: ${e.message}`, "error");
      if (e.name === "OperacionCanceladaError") {
        log("Depuracion interrumpida: no se borro ningun objeto.", "warn");
        return resultado({ eliminados: 0, fallidos, desvinculados });
      }
    } finally {
      onProgreso(++hechos, totalPasos);
    }
  }

  // --- Fase 2: borrar, contenedores antes que contenidos ---
  let eliminados = 0;

  for (const objeto of aBorrar) {
    // Si no se pudo desvincular de alguno de sus grupos, el DELETE fallaria
    // igual: se omite con un motivo claro en vez de generar un error crudo.
    const sinDesvincular = (objeto.gruposContenedores || [])
      .filter((g) => gruposFallidos.has(claveGrupo(g)))
      .map((g) => `'${g.name}'`);

    if (sinDesvincular.length) {
      log(
        `${objeto.name}: no se borra porque no se pudo quitar del grupo ${sinDesvincular.join(", ")}.`,
        "error"
      );
      onProgreso(++hechos, totalPasos);
      continue;
    }

    try {
      log(`Eliminando ${objeto.kind} '${objeto.name}' (${objeto.scope})...`, "debug");
      await eliminarObjeto(target, objeto);
      log(`${objeto.kind} '${objeto.name}' eliminado de la candidate config.`, "ok");
      eliminados++;
      eliminadosClaves.push(clave(objeto));
    } catch (e) {
      fallidos++;
      log(`${objeto.name}: ${e.message}`, "error");
      if (e.name === "OperacionCanceladaError") break;
    } finally {
      onProgreso(++hechos, totalPasos);
    }
  }

  log(
    `Depuracion finalizada: ${eliminados} eliminado(s), ` +
      `${desvinculados} desvinculado(s) de grupos que se conservan, ` +
      `${fallidos} con error, ${bloqueados.length} omitido(s)` +
      (pendientes.length ? `, ${pendientes.length} pendiente(s) para la siguiente sesion` : "") +
      `. REVISA y haz COMMIT manualmente en la GUI.`,
    eliminados ? "ok" : "warn"
  );

  return resultado({ eliminados, fallidos, desvinculados });
}

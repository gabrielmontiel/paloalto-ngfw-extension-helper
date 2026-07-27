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
 * @returns {{ediciones: Array, aBorrar: Array, bloqueados: Array}}
 */
export function planificarDepuracion(seleccion) {
  const seleccionados = new Set(seleccion.map(clave));

  // --- 1. Ediciones de grupo necesarias (grupos NO marcados) ---
  // grupoKey -> { grupo, quitar: string[], miembros: string[] }
  const ediciones = new Map();

  for (const objeto of seleccion) {
    for (const g of objeto.gruposContenedores || []) {
      if (seleccionados.has(claveGrupo(g))) continue; // se borra el grupo entero
      const gk = claveGrupo(g);
      if (!ediciones.has(gk)) {
        ediciones.set(gk, { grupo: g, quitar: [], miembros: g.miembros || [] });
      }
      ediciones.get(gk).quitar.push(objeto.name);
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
  const aBorrar = ordenarPorDependencias(candidatos, new Set(candidatos.map(clave)));

  return { ediciones: [...ediciones.values()], aBorrar, bloqueados };
}

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
 * @param {{target: object, seleccion: Array<object>}} config
 * @param {(mensaje: string, nivel?: string) => void} log
 * @param {(hechos: number, total: number) => void} onProgreso
 * @returns {{eliminados, fallidos, omitidos, desvinculados}}
 */
export async function depurarObjetos(config, log, onProgreso) {
  const { target, seleccion } = config;

  if (!seleccion?.length) {
    throw new Error("No se selecciono ningun objeto para depurar.");
  }

  const version = restVersionFromSw(target.swVersion);
  const { ediciones, aBorrar, bloqueados } = planificarDepuracion(seleccion);

  log(`Depuracion: REST API ${version} en ${target.host}.`);
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
    return { eliminados: 0, fallidos: 0, omitidos: bloqueados.length, desvinculados: 0 };
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
      }
    } catch (e) {
      fallidos++;
      gruposFallidos.add(claveGrupo(g));
      log(`${g.name}: ${e.message}`, "error");
      if (e.name === "OperacionCanceladaError") {
        log("Depuracion interrumpida: no se borro ningun objeto.", "warn");
        return { eliminados: 0, fallidos, omitidos: bloqueados.length, desvinculados };
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
      `${fallidos} con error, ${bloqueados.length} omitido(s). ` +
      `REVISA y haz COMMIT manualmente en la GUI.`,
    eliminados ? "ok" : "warn"
  );

  return { eliminados, fallidos, omitidos: bloqueados.length, desvinculados };
}

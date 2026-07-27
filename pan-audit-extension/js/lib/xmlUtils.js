// js/lib/xmlUtils.js
// Ayudas minimas sobre DOMParser para que el resto del codigo no repita
// boilerplate de querySelector. (Tomado de pan-audit-extension sin cambios
// de fondo.)

export function parseXml(xmlString) {
  const doc = new DOMParser().parseFromString(xmlString, "application/xml");
  const err = doc.querySelector("parsererror");
  if (err) {
    throw new Error("La respuesta del equipo no es XML valido: " + err.textContent);
  }
  return doc;
}

// Las respuestas de la API PAN-OS tienen esta forma:
//   <response status="success"><result>...</result></response>
// y en error:
//   <response status="error" code="..."><msg><line>...</line></msg></response>
export function unwrapApiResponse(doc) {
  const response = doc.documentElement;
  if (!response || response.tagName !== "response") {
    throw new Error("Respuesta inesperada de la API (sin raiz <response>).");
  }
  const status = response.getAttribute("status");
  if (status !== "success") {
    const msg = doc.querySelector("msg")?.textContent?.trim() || "Error no especificado por el equipo";
    const code = response.getAttribute("code") || "";
    throw new Error(`Error de la API PAN-OS ${code}: ${msg}`);
  }
  return response.querySelector("result");
}

// Hijos DIRECTOS con un tag dado (no descendientes) — la config de PAN-OS
// anida los mismos nombres de tag en muchos niveles (p. ej. "entry"), asi
// que querySelectorAll solo sobre-coincide.
export function children(el, tag) {
  if (!el) return [];
  return Array.from(el.children).filter((c) => c.tagName === tag);
}

export function child(el, tag) {
  return children(el, tag)[0] || null;
}

// Miembros de una lista <member>x</member><member>y</member>.
export function memberList(el) {
  if (!el) return [];
  return children(el, "member").map((m) => m.textContent.trim());
}

export function entryName(entryEl) {
  return entryEl.getAttribute("name");
}

export function textOf(el) {
  return el ? el.textContent.trim() : "";
}

// lib/xmlUtils.js
// Small helpers around DOMParser so the rest of the code isn't littered
// with querySelector boilerplate.

export function parseXml(xmlString) {
  const doc = new DOMParser().parseFromString(xmlString, "application/xml");
  const err = doc.querySelector("parsererror");
  if (err) {
    throw new Error("Failed to parse XML response from firewall: " + err.textContent);
  }
  return doc;
}

// PAN-OS API responses look like:
// <response status="success"><result>...</result></response>
// or on error:
// <response status="error" code="..."><msg><line>...</line></msg></response>
export function unwrapApiResponse(doc) {
  const response = doc.documentElement;
  if (!response || response.tagName !== "response") {
    throw new Error("Unexpected API response shape (no <response> root).");
  }
  const status = response.getAttribute("status");
  if (status !== "success") {
    const msg = doc.querySelector("msg")?.textContent?.trim() || "Unknown error";
    const code = response.getAttribute("code") || "";
    throw new Error(`PAN-OS API error ${code}: ${msg}`);
  }
  return response.querySelector("result");
}

// Direct children with a given tag name (not descendants) — PAN-OS config
// nests the same tag names at many levels (e.g. "entry"), so
// querySelectorAll alone over-matches.
export function children(el, tag) {
  if (!el) return [];
  return Array.from(el.children).filter((c) => c.tagName === tag);
}

export function child(el, tag) {
  return children(el, tag)[0] || null;
}

// Members of a <member>x</member><member>y</member> list.
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

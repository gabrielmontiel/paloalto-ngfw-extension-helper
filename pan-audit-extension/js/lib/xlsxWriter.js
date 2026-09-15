// js/lib/xlsxWriter.js
// Generador minimo de archivos .xlsx (Office Open XML), sin dependencias.
//
// Un .xlsx es un zip de XML. Aqui se escribe ese XML a mano y se empaqueta
// con un zip sin compresion (metodo STORE): Excel y LibreOffice lo abren
// igual, y evita tener que implementar deflate. El precio es el tamano, que
// para reportes de texto sigue siendo razonable.
//
// Cubre lo que usan los reportes de PAN Helper: texto, numeros, formulas con
// valor precalculado, estilos (fuente, relleno, borde, alineacion, formato
// numerico), celdas combinadas, ancho de columnas, alto de filas, paneles
// fijos, autofiltro, ocultar cuadricula y graficos de radar.
//
// Modulo puro: no usa el DOM ni chrome.*; devuelve un Uint8Array.

// ---------------------------------------------------------------------------
//  Utilidades
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

function escXml(s) {
  return String(s)
    // Caracteres de control que XML 1.0 no admite (rompen el archivo entero).
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** 1 -> A, 27 -> AA */
export function letraColumna(n) {
  let s = "";
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

export function ref(fila, col) {
  return `${letraColumna(col)}${fila}`;
}

/** "C4" -> {fila: 4, col: 3} */
function parsearRef(r) {
  const m = /^([A-Z]+)(\d+)$/.exec(r);
  if (!m) throw new Error(`Referencia de celda invalida: ${r}`);
  let col = 0;
  for (const ch of m[1]) col = col * 26 + (ch.charCodeAt(0) - 64);
  return { fila: Number(m[2]), col };
}

/** Nombre de hoja citado para formulas: 'BP Mode'!$A$1 */
export function nombreHojaFormula(nombre) {
  return `'${String(nombre).replace(/'/g, "''")}'`;
}

// ---------------------------------------------------------------------------
//  Zip (STORE)
// ---------------------------------------------------------------------------

const TABLA_CRC = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = TABLA_CRC[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * @param {Array<[string, Uint8Array]>} archivos
 * @returns {Uint8Array}
 */
export function empaquetarZip(archivos, fecha = new Date()) {
  const dosHora = ((fecha.getHours() << 11) | (fecha.getMinutes() << 5) | (fecha.getSeconds() >> 1)) & 0xffff;
  const dosFecha = (((fecha.getFullYear() - 1980) << 9) | ((fecha.getMonth() + 1) << 5) | fecha.getDate()) & 0xffff;

  const locales = [];
  const centrales = [];
  let offset = 0;

  for (const [nombre, datos] of archivos) {
    const nombreBytes = enc.encode(nombre);
    const crc = crc32(datos);

    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);          // version necesaria
    local.setUint16(6, 0x0800, true);      // bit 11: nombres en UTF-8
    local.setUint16(8, 0, true);           // metodo STORE
    local.setUint16(10, dosHora, true);
    local.setUint16(12, dosFecha, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, datos.length, true);
    local.setUint32(22, datos.length, true);
    local.setUint16(26, nombreBytes.length, true);
    local.setUint16(28, 0, true);
    locales.push(new Uint8Array(local.buffer), nombreBytes, datos);

    const central = new DataView(new ArrayBuffer(46));
    central.setUint32(0, 0x02014b50, true);
    central.setUint16(4, 20, true);
    central.setUint16(6, 20, true);
    central.setUint16(8, 0x0800, true);
    central.setUint16(10, 0, true);
    central.setUint16(12, dosHora, true);
    central.setUint16(14, dosFecha, true);
    central.setUint32(16, crc, true);
    central.setUint32(20, datos.length, true);
    central.setUint32(24, datos.length, true);
    central.setUint16(28, nombreBytes.length, true);
    central.setUint32(42, offset, true);
    centrales.push(new Uint8Array(central.buffer), nombreBytes);

    offset += 30 + nombreBytes.length + datos.length;
  }

  const tamCentral = centrales.reduce((s, b) => s + b.length, 0);
  const fin = new DataView(new ArrayBuffer(22));
  fin.setUint32(0, 0x06054b50, true);
  fin.setUint16(8, archivos.length, true);
  fin.setUint16(10, archivos.length, true);
  fin.setUint32(12, tamCentral, true);
  fin.setUint32(16, offset, true);

  const partes = [...locales, ...centrales, new Uint8Array(fin.buffer)];
  const total = partes.reduce((s, b) => s + b.length, 0);
  const salida = new Uint8Array(total);
  let p = 0;
  for (const b of partes) {
    salida.set(b, p);
    p += b.length;
  }
  return salida;
}

// ---------------------------------------------------------------------------
//  Estilos
// ---------------------------------------------------------------------------

/**
 * Estilo de celda (todos los campos opcionales):
 *   { fuente: {tam, negrita, color, nombre},
 *     relleno: "RRGGBB", borde: "RRGGBB",
 *     h: "left"|"center"|"right", v: "top"|"center"|"bottom",
 *     ajustar: true, sangria: 1, formato: "0.0%" }
 */
class Estilos {
  constructor(fuentePorDefecto = "Calibri") {
    this.fuentePorDefecto = fuentePorDefecto;
    this.fuentes = [`<font><sz val="11"/><name val="${fuentePorDefecto}"/></font>`];
    this.rellenos = [
      '<fill><patternFill patternType="none"/></fill>',
      '<fill><patternFill patternType="gray125"/></fill>',
    ];
    this.bordes = ["<border><left/><right/><top/><bottom/><diagonal/></border>"];
    this.formatos = [];            // [id, codigo]
    this.xfs = ['<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'];
    this.indices = new Map();      // clave -> indice (dedupe)
  }

  _registrar(lista, prefijo, xml) {
    const clave = prefijo + xml;
    if (!this.indices.has(clave)) {
      lista.push(xml);
      this.indices.set(clave, lista.length - 1);
    }
    return this.indices.get(clave);
  }

  _formato(codigo) {
    if (!codigo || codigo === "General") return 0;
    const integrados = { "0": 1, "0.00": 2, "#,##0": 3, "#,##0.00": 4, "0%": 9, "0.00%": 10 };
    if (codigo in integrados) return integrados[codigo];
    const existente = this.formatos.find(([, c]) => c === codigo);
    if (existente) return existente[0];
    const id = 164 + this.formatos.length;
    this.formatos.push([id, codigo]);
    return id;
  }

  indice(estilo) {
    if (!estilo) return 0;
    const clave = JSON.stringify(estilo);
    const cache = this.indices.get("s:" + clave);
    if (cache !== undefined) return cache;

    const f = estilo.fuente || {};
    const fuenteXml =
      "<font>" +
      (f.negrita ? "<b/>" : "") +
      `<sz val="${f.tam || 11}"/>` +
      (f.color ? `<color rgb="FF${f.color}"/>` : "") +
      `<name val="${escXml(f.nombre || this.fuentePorDefecto)}"/>` +
      "</font>";
    const fontId = this._registrar(this.fuentes, "f:", fuenteXml);

    const fillId = estilo.relleno
      ? this._registrar(
          this.rellenos,
          "r:",
          `<fill><patternFill patternType="solid"><fgColor rgb="FF${estilo.relleno}"/><bgColor indexed="64"/></patternFill></fill>`
        )
      : 0;

    const lado = (t) => `<${t} style="thin"><color rgb="FF${estilo.borde}"/></${t}>`;
    const borderId = estilo.borde
      ? this._registrar(
          this.bordes,
          "b:",
          `<border>${lado("left")}${lado("right")}${lado("top")}${lado("bottom")}<diagonal/></border>`
        )
      : 0;

    const numFmtId = this._formato(estilo.formato);

    const alin = [];
    if (estilo.h) alin.push(`horizontal="${estilo.h}"`);
    if (estilo.v) alin.push(`vertical="${estilo.v}"`);
    if (estilo.ajustar) alin.push('wrapText="1"');
    if (estilo.sangria) alin.push(`indent="${estilo.sangria}"`);

    const xf =
      `<xf numFmtId="${numFmtId}" fontId="${fontId}" fillId="${fillId}" borderId="${borderId}" xfId="0"` +
      ' applyFont="1"' +
      (fillId ? ' applyFill="1"' : "") +
      (borderId ? ' applyBorder="1"' : "") +
      (numFmtId ? ' applyNumberFormat="1"' : "") +
      (alin.length ? ` applyAlignment="1"><alignment ${alin.join(" ")}/></xf>` : "/>");

    this.xfs.push(xf);
    const idx = this.xfs.length - 1;
    this.indices.set("s:" + clave, idx);
    return idx;
  }

  xml() {
    const numFmts = this.formatos.length
      ? `<numFmts count="${this.formatos.length}">` +
        this.formatos.map(([id, c]) => `<numFmt numFmtId="${id}" formatCode="${escXml(c)}"/>`).join("") +
        "</numFmts>"
      : "";
    return (
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
      numFmts +
      `<fonts count="${this.fuentes.length}">${this.fuentes.join("")}</fonts>` +
      `<fills count="${this.rellenos.length}">${this.rellenos.join("")}</fills>` +
      `<borders count="${this.bordes.length}">${this.bordes.join("")}</borders>` +
      '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
      `<cellXfs count="${this.xfs.length}">${this.xfs.join("")}</cellXfs>` +
      '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
      "</styleSheet>"
    );
  }
}

// ---------------------------------------------------------------------------
//  Hoja
// ---------------------------------------------------------------------------

export class Hoja {
  constructor(libro, nombre) {
    if (!nombre || nombre.length > 31 || /[\\/?*[\]:]/.test(nombre)) {
      throw new Error(`Nombre de hoja invalido para Excel: '${nombre}'`);
    }
    this.libro = libro;
    this.nombre = nombre;
    this.filas = new Map();     // fila -> Map(col -> {valor, s})
    this.altos = new Map();
    this.anchos = new Map();
    this.combinadas = [];
    this.congelada = null;
    this.rangoFiltro = null;
    this.cuadricula = true;
    this.graficos = [];
    this.maxFila = 0;
    this.maxCol = 0;
  }

  /**
   * Escribe una celda. valor: string | number | boolean | null |
   * {formula: "SUM(A1:A3)", valor: 6}   (valor = resultado precalculado)
   * Devuelve la hoja para encadenar.
   */
  celda(fila, col, valor, estilo) {
    if (!this.filas.has(fila)) this.filas.set(fila, new Map());
    const actual = this.filas.get(fila).get(col) || {};
    this.filas.get(fila).set(col, {
      valor: valor === undefined ? actual.valor : valor,
      s: estilo === undefined ? actual.s || 0 : this.libro.estilos.indice(estilo),
    });
    this.maxFila = Math.max(this.maxFila, fila);
    this.maxCol = Math.max(this.maxCol, col);
    return this;
  }

  /** Aplica un estilo a una celda sin cambiar su valor. */
  estilo(fila, col, estilo) {
    return this.celda(fila, col, undefined, estilo);
  }

  combinar(fila1, col1, fila2, col2) {
    this.combinadas.push(`${ref(fila1, col1)}:${ref(fila2, col2)}`);
    return this;
  }

  ancho(col, caracteres) {
    this.anchos.set(col, caracteres);
    return this;
  }

  alto(fila, puntos) {
    this.altos.set(fila, puntos);
    return this;
  }

  /** Congela filas/columnas por encima/izquierda de la celda: congelar("A4"). */
  congelar(celdaRef) {
    this.congelada = celdaRef;
    return this;
  }

  filtro(rango) {
    this.rangoFiltro = rango;
    return this;
  }

  sinCuadricula() {
    this.cuadricula = false;
    return this;
  }

  /**
   * Grafico de radar.
   * @param {object} g
   * @param {string} g.titulo
   * @param {{fila1:number, fila2:number, col:number}} g.categorias
   * @param {Array<{nombreFila:number, col:number, color:string}>} g.series
   *        (valores en filas categorias.fila1..fila2 de la columna col)
   * @param {string} g.ancla   celda superior izquierda, p. ej. "E3"
   * @param {number} [g.anchoCm=17]
   * @param {number} [g.altoCm=11]
   * @param {{min:number, max:number}} [g.escala]
   */
  radar(g) {
    this.graficos.push({ tipo: "radar", anchoCm: 17, altoCm: 11, ...g });
    return this;
  }

  _valorCelda(fila, col) {
    return this.filas.get(fila)?.get(col)?.valor;
  }

  _xmlCelda(r, c, { valor, s }) {
    const atrS = s ? ` s="${s}"` : "";
    const rr = ref(r, c);
    if (valor === null || valor === undefined || valor === "") return `<c r="${rr}"${atrS}/>`;

    if (typeof valor === "object" && "formula" in valor) {
      const f = `<f>${escXml(String(valor.formula).replace(/^=/, ""))}</f>`;
      const v = valor.valor;
      if (typeof v === "number" && Number.isFinite(v)) return `<c r="${rr}"${atrS}>${f}<v>${v}</v></c>`;
      if (typeof v === "string") return `<c r="${rr}"${atrS} t="str">${f}<v>${escXml(v)}</v></c>`;
      return `<c r="${rr}"${atrS}>${f}</c>`;
    }
    if (typeof valor === "number") {
      return Number.isFinite(valor) ? `<c r="${rr}"${atrS}><v>${valor}</v></c>` : `<c r="${rr}"${atrS}/>`;
    }
    if (typeof valor === "boolean") return `<c r="${rr}"${atrS} t="b"><v>${valor ? 1 : 0}</v></c>`;
    return `<c r="${rr}"${atrS} t="s"><v>${this.libro._cadena(String(valor))}</v></c>`;
  }

  xml(idDibujo) {
    let vista = `<sheetView workbookViewId="0"${this.cuadricula ? "" : ' showGridLines="0"'}`;
    if (this.congelada) {
      const { fila, col } = parsearRef(this.congelada);
      const xs = col - 1;
      const ys = fila - 1;
      const panel = xs && ys ? "bottomRight" : ys ? "bottomLeft" : "topRight";
      vista +=
        `><pane${xs ? ` xSplit="${xs}"` : ""}${ys ? ` ySplit="${ys}"` : ""} topLeftCell="${this.congelada}"` +
        ` activePane="${panel}" state="frozen"/><selection pane="${panel}"/></sheetView>`;
    } else {
      vista += "/>";
    }

    const cols = [...this.anchos.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([c, w]) => `<col min="${c}" max="${c}" width="${w}" customWidth="1"/>`)
      .join("");

    const filasOrdenadas = [...new Set([...this.filas.keys(), ...this.altos.keys()])].sort((a, b) => a - b);
    const datos = filasOrdenadas
      .map((r) => {
        const celdas = this.filas.get(r);
        const alto = this.altos.get(r);
        const atrAlto = alto ? ` ht="${alto}" customHeight="1"` : "";
        if (!celdas || !celdas.size) return `<row r="${r}"${atrAlto}/>`;
        const cuerpo = [...celdas.entries()]
          .sort((a, b) => a[0] - b[0])
          .map(([c, celda]) => this._xmlCelda(r, c, celda))
          .join("");
        return `<row r="${r}"${atrAlto}>${cuerpo}</row>`;
      })
      .join("");

    const dim = this.maxFila ? `A1:${ref(this.maxFila, Math.max(1, this.maxCol))}` : "A1";

    return (
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ' +
      'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
      `<dimension ref="${dim}"/>` +
      `<sheetViews>${vista}</sheetViews>` +
      '<sheetFormatPr defaultRowHeight="15"/>' +
      (cols ? `<cols>${cols}</cols>` : "") +
      `<sheetData>${datos}</sheetData>` +
      (this.rangoFiltro ? `<autoFilter ref="${this.rangoFiltro}"/>` : "") +
      (this.combinadas.length
        ? `<mergeCells count="${this.combinadas.length}">` +
          this.combinadas.map((m) => `<mergeCell ref="${m}"/>`).join("") +
          "</mergeCells>"
        : "") +
      '<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>' +
      (idDibujo ? '<drawing r:id="rId1"/>' : "") +
      "</worksheet>"
    );
  }
}

// ---------------------------------------------------------------------------
//  Graficos
// ---------------------------------------------------------------------------

const EMU_POR_CM = 360000;

function xmlDibujo(graficos, idsGrafico) {
  const anclas = graficos
    .map((g, i) => {
      const { fila, col } = parsearRef(g.ancla);
      return (
        "<xdr:oneCellAnchor>" +
        `<xdr:from><xdr:col>${col - 1}</xdr:col><xdr:colOff>0</xdr:colOff>` +
        `<xdr:row>${fila - 1}</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>` +
        `<xdr:ext cx="${Math.round(g.anchoCm * EMU_POR_CM)}" cy="${Math.round(g.altoCm * EMU_POR_CM)}"/>` +
        '<xdr:graphicFrame macro="">' +
        `<xdr:nvGraphicFramePr><xdr:cNvPr id="${i + 2}" name="Grafico ${i + 1}"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr>` +
        '<xdr:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/></xdr:xfrm>' +
        '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">' +
        '<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" ' +
        `xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="rId${idsGrafico[i]}"/>` +
        "</a:graphicData></a:graphic></xdr:graphicFrame><xdr:clientData/></xdr:oneCellAnchor>"
      );
    })
    .join("");
  return (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" ' +
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">' +
    anclas +
    "</xdr:wsDr>"
  );
}

function xmlRadar(hoja, g) {
  const h = nombreHojaFormula(hoja.nombre);
  const { fila1, fila2, col: colCat } = g.categorias;
  const letraCat = letraColumna(colCat);

  const cacheTexto = (valores) =>
    `<c:strCache><c:ptCount val="${valores.length}"/>` +
    valores.map((v, i) => `<c:pt idx="${i}"><c:v>${escXml(v ?? "")}</c:v></c:pt>`).join("") +
    "</c:strCache>";

  const categorias = [];
  for (let r = fila1; r <= fila2; r++) categorias.push(String(hoja._valorCelda(r, colCat) ?? ""));

  const series = g.series
    .map((s, i) => {
      const letra = letraColumna(s.col);
      const nombre = String(hoja._valorCelda(s.nombreFila, s.col) ?? `Serie ${i + 1}`);
      const puntos = [];
      for (let r = fila1; r <= fila2; r++) {
        const v = hoja._valorCelda(r, s.col);
        // Los "—" (sin datos) quedan como huecos en el grafico.
        if (typeof v === "number" && Number.isFinite(v)) puntos.push(`<c:pt idx="${r - fila1}"><c:v>${v}</c:v></c:pt>`);
      }
      return (
        `<c:ser><c:idx val="${i}"/><c:order val="${i}"/>` +
        `<c:tx><c:strRef><c:f>${h}!$${letra}$${s.nombreFila}</c:f>${cacheTexto([nombre])}</c:strRef></c:tx>` +
        `<c:spPr><a:ln w="28575"><a:solidFill><a:srgbClr val="${s.color}"/></a:solidFill></a:ln></c:spPr>` +
        `<c:marker><c:symbol val="circle"/><c:size val="6"/><c:spPr><a:solidFill><a:srgbClr val="${s.color}"/></a:solidFill>` +
        `<a:ln><a:solidFill><a:srgbClr val="${s.color}"/></a:solidFill></a:ln></c:spPr></c:marker>` +
        `<c:cat><c:strRef><c:f>${h}!$${letraCat}$${fila1}:$${letraCat}$${fila2}</c:f>${cacheTexto(categorias)}</c:strRef></c:cat>` +
        `<c:val><c:numRef><c:f>${h}!$${letra}$${fila1}:$${letra}$${fila2}</c:f>` +
        `<c:numCache><c:formatCode>General</c:formatCode><c:ptCount val="${fila2 - fila1 + 1}"/>${puntos.join("")}</c:numCache>` +
        "</c:numRef></c:val></c:ser>"
      );
    })
    .join("");

  const escala = g.escala
    ? `<c:scaling><c:orientation val="minMax"/><c:max val="${g.escala.max}"/><c:min val="${g.escala.min}"/></c:scaling>`
    : '<c:scaling><c:orientation val="minMax"/></c:scaling>';

  return (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" ' +
    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ' +
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
    '<c:roundedCorners val="0"/><c:chart>' +
    `<c:title><c:tx><c:rich><a:bodyPr/><a:p><a:pPr><a:defRPr sz="1200" b="1"/></a:pPr>` +
    `<a:r><a:rPr lang="es-ES" sz="1200" b="1"/><a:t>${escXml(g.titulo || "")}</a:t></a:r></a:p></c:rich></c:tx>` +
    '<c:overlay val="0"/></c:title><c:autoTitleDeleted val="0"/>' +
    '<c:plotArea><c:layout/><c:radarChart><c:radarStyle val="marker"/><c:varyColors val="0"/>' +
    series +
    '<c:axId val="500000001"/><c:axId val="500000002"/></c:radarChart>' +
    '<c:catAx><c:axId val="500000001"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/>' +
    '<c:axPos val="b"/><c:majorGridlines/><c:numFmt formatCode="General" sourceLinked="1"/>' +
    '<c:majorTickMark val="out"/><c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/>' +
    '<c:crossAx val="500000002"/><c:crosses val="autoZero"/><c:auto val="1"/><c:lblAlgn val="ctr"/>' +
    '<c:lblOffset val="100"/><c:noMultiLvlLbl val="0"/></c:catAx>' +
    `<c:valAx><c:axId val="500000002"/>${escala}<c:delete val="0"/><c:axPos val="l"/><c:majorGridlines/>` +
    '<c:numFmt formatCode="General" sourceLinked="0"/><c:majorTickMark val="cross"/><c:minorTickMark val="none"/>' +
    '<c:tickLblPos val="nextTo"/><c:crossAx val="500000001"/><c:crosses val="autoZero"/>' +
    '<c:crossBetween val="between"/></c:valAx></c:plotArea>' +
    '<c:legend><c:legendPos val="b"/><c:overlay val="0"/></c:legend>' +
    '<c:plotVisOnly val="1"/><c:dispBlanksAs val="gap"/></c:chart></c:chartSpace>'
  );
}

// ---------------------------------------------------------------------------
//  Libro
// ---------------------------------------------------------------------------

export class Libro {
  constructor({ fuente = "Calibri" } = {}) {
    this.hojas = [];
    this.estilos = new Estilos(fuente);
    this.cadenas = [];
    this.indiceCadenas = new Map();
  }

  /** Crea una hoja. posicion: indice donde insertarla (por defecto, al final). */
  hoja(nombre, posicion) {
    if (this.hojas.some((h) => h.nombre.toLowerCase() === nombre.toLowerCase())) {
      throw new Error(`Hoja duplicada: '${nombre}'`);
    }
    const h = new Hoja(this, nombre);
    if (posicion === undefined || posicion >= this.hojas.length) this.hojas.push(h);
    else this.hojas.splice(posicion, 0, h);
    return h;
  }

  _cadena(texto) {
    let i = this.indiceCadenas.get(texto);
    if (i === undefined) {
      i = this.cadenas.length;
      this.cadenas.push(texto);
      this.indiceCadenas.set(texto, i);
    }
    return i;
  }

  /** @returns {Uint8Array} contenido del .xlsx */
  aBytes() {
    if (!this.hojas.length) throw new Error("El libro no tiene hojas.");

    const archivos = [];
    const agregar = (nombre, texto) => archivos.push([nombre, enc.encode(texto)]);

    // Las hojas se serializan primero: registran las cadenas compartidas.
    const tipos = [];
    let nGrafico = 0;
    let nDibujo = 0;
    const hojasXml = this.hojas.map((hoja, i) => {
      const n = i + 1;
      let idDibujo = null;
      if (hoja.graficos.length) {
        idDibujo = ++nDibujo;
        const idsRel = hoja.graficos.map((_, j) => j + 1);
        const rels = hoja.graficos
          .map((g, j) => {
            const idGraf = ++nGrafico;
            agregar(`xl/charts/chart${idGraf}.xml`, xmlRadar(hoja, g));
            tipos.push(`<Override PartName="/xl/charts/chart${idGraf}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/>`);
            return `<Relationship Id="rId${idsRel[j]}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" Target="../charts/chart${idGraf}.xml"/>`;
          })
          .join("");
        agregar(`xl/drawings/drawing${idDibujo}.xml`, xmlDibujo(hoja.graficos, idsRel));
        agregar(
          `xl/drawings/_rels/drawing${idDibujo}.xml.rels`,
          '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels}</Relationships>`
        );
        agregar(
          `xl/worksheets/_rels/sheet${n}.xml.rels`,
          '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
            `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing${idDibujo}.xml"/>` +
            "</Relationships>"
        );
        tipos.push(`<Override PartName="/xl/drawings/drawing${idDibujo}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>`);
      }
      return hoja.xml(idDibujo);
    });

    hojasXml.forEach((xml, i) => {
      agregar(`xl/worksheets/sheet${i + 1}.xml`, xml);
      tipos.push(`<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`);
    });

    agregar(
      "xl/sharedStrings.xml",
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="${this.cadenas.length}" uniqueCount="${this.cadenas.length}">` +
        this.cadenas.map((t) => `<si><t xml:space="preserve">${escXml(t)}</t></si>`).join("") +
        "</sst>"
    );
    agregar("xl/styles.xml", this.estilos.xml());

    // Los autofiltros de Excel se apoyan en un nombre definido oculto por hoja.
    const nombres = this.hojas
      .map((h, i) =>
        h.rangoFiltro
          ? `<definedName name="_xlnm._FilterDatabase" localSheetId="${i}" hidden="1">` +
            `${escXml(nombreHojaFormula(h.nombre))}!${h.rangoFiltro.replace(/([A-Z]+)(\d+)/g, "$$$1$$$2")}</definedName>`
          : ""
      )
      .join("");

    agregar(
      "xl/workbook.xml",
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ' +
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
        '<bookViews><workbookView activeTab="0"/></bookViews><sheets>' +
        this.hojas.map((h, i) => `<sheet name="${escXml(h.nombre)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join("") +
        "</sheets>" +
        (nombres ? `<definedNames>${nombres}</definedNames>` : "") +
        // Recalcula al abrir: los valores precalculados son solo el respaldo.
        '<calcPr calcId="191029" fullCalcOnLoad="1"/></workbook>'
    );

    const n = this.hojas.length;
    agregar(
      "xl/_rels/workbook.xml.rels",
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        this.hojas
          .map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`)
          .join("") +
        `<Relationship Id="rId${n + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
        `<Relationship Id="rId${n + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>` +
        "</Relationships>"
    );

    agregar(
      "_rels/.rels",
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
        "</Relationships>"
    );

    agregar(
      "[Content_Types].xml",
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
        '<Default Extension="xml" ContentType="application/xml"/>' +
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
        '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>' +
        tipos.join("") +
        "</Types>"
    );

    // [Content_Types].xml primero, como hacen Excel y openpyxl.
    archivos.sort((a, b) => (a[0] === "[Content_Types].xml" ? -1 : b[0] === "[Content_Types].xml" ? 1 : 0));
    return empaquetarZip(archivos);
  }
}

export const MIME_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

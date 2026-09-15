# Notas de diseño — PAN Helper

Este documento es para quien toca el código. Explica por qué la extensión
está construida así, qué se tomó de cada proyecto de origen y cómo agregar un
módulo nuevo.

- **Qué hace y cómo se usa** → [README del proyecto](../README.md)
- **Historial de versiones** → [CHANGELOG](../CHANGELOG.md)

## Qué se tomó de cada proyecto

De **pan-audit-extension**:

- **Conexiones guardadas**: usuario y contraseña se ingresan una sola vez;
  se cambian por API key (`keygen`) y solo la key se guarda en
  `chrome.storage.local`. Todos los módulos reutilizan la conexión — no se
  vuelve a escribir la credencial.
- **Auditoría**: reglas deshabilitadas, objetos sin uso, posibles sombras y
  malas prácticas en las políticas (any/any, sin perfiles de seguridad, sin
  log-end, sin tags).
- **La interfaz**: navbar, dashboard con tarjetas de resumen, pestañas y
  tablas, página de Conexiones.

De **PAN-helper v0.1**:

- **Módulo de backups** (configuración + device-state) — la lógica verificada
  en producción, ahora sobre conexiones guardadas.
- **Módulo de hardening App-ID** (recomendación de apps para
  `application = any` a partir de logs de tráfico).
- **La organización por módulos**: `js/modules/<nombre>.js` exporta una
  función `(config, log, onProgreso) => Promise`; `js/dashboard.js` es el
  único lugar que los registra.
- **La consola de registro**, ahora con más detalle: el checkbox **Detalle**
  muestra cada llamada a la API (tipo, acción, host), los ámbitos y conteos
  del análisis, y los jobs de logs.

## Qué se corrigió / eliminó a propósito

- **Sin Policy Optimizer.** Se eliminó la sección completa, incluida la única
  función de escritura que existía (`setConfigNode`). No hay código capaz de
  escribir en el equipo.
- **Objetos sin uso en cascada.** Si un address no aparece en ninguna regla
  pero es miembro de un address-group que a su vez está sin uso, el hallazgo
  lo dice explícitamente: *"Sin uso porque el address-group 'X' al que
  pertenece tampoco se usa. Eliminar primero el grupo y después este
  objeto."* La tabla además se ordena con los grupos primero (el orden seguro
  de eliminación) y marca estos casos con la insignia `en grupo sin uso`.
  Borrar el miembro antes que el grupo produce error de referencia en el
  firewall — por eso el aviso.
- **Sin nombres de políticas reales en la UI.** Los placeholders son
  genéricos (`rule-1`, `rule-2`); no queda información de clientes en el
  código ni en la interfaz.

## Modelo de escritura: sin commit, escritura mínima y explícita

Tres capas de red, cada una con su propia garantía. Las dos primeras hablan
con el firewall; la tercera, solo con la nube de Palo Alto:

- **`js/lib/panApi.js` (XML API)** — lectura estricta con **una sola
  excepción**: guardar la definición de un Custom Report.
  `verificarSoloLectura()` corre en todas las rutas y bloquea
  `commit`/`import`/`user-id`, cualquier `config action` que no sea
  `get`/`show`, y comandos operacionales de escritura. La excepción admite
  únicamente `action=set` cuyo xpath caiga dentro de un contenedor de
  reports (`/config/shared/reports` o el equivalente por vsys): no alcanza a
  políticas, objetos ni nada más, `delete` sigue bloqueado incluso ahí, y
  sigue sin existir commit. Está cubierta por pruebas que verifican tanto lo
  que permite como lo que rechaza.
- **`js/lib/panRestApi.js` (REST API)** — el único archivo que puede
  escribir. Un guard de endpoint rechaza cualquier ruta distinta de
  `Policies/Security{,Pre,Post}Rules` (GET/crear/actualizar/move) y
  `Objects/{Addresses, AddressGroups, Services, ServiceGroups}`
  (GET/PUT/DELETE). **`DELETE` solo se admite sobre objetos: ninguna regla
  se elimina nunca.** El `PUT` sobre reglas existe solo para el merge de
  aplicaciones, y el módulo verifica que el nombre lleve el sufijo antes de
  llamarlo, así que la regla original nunca se modifica. Todo lo que escribe
  queda en la **candidate config**. **No existe commit en ninguna parte de la
  extensión**: revisar y hacer commit (y en Panorama, el push) en la GUI es
  obligatorio y siempre manual.

- **`js/lib/scmApi.js` (Strata Cloud Manager Posture API)** — no toca el
  firewall. Solo se usa en el origen "SCM" de Best Practices, después de que
  el usuario marca la confirmación de que la configuración saldrá hacia Palo
  Alto. Una lista de hosts (`auth.apps.paloaltonetworks.com`,
  `api.sase.paloaltonetworks.com`, `storage.googleapis.com`) se verifica antes
  de cada petición, incluidos el `upload_url` y el `report_url` que devuelve
  SCM. Las credenciales viven solo en memoria; el registro nunca incluye el
  secret, el token ni la query de los URL firmados. Comparte la señal de
  cancelación de `panApi.js`.

Las dos operaciones de escritura ("Clonar y ajustar" y "Depurar") solo
corren tras una confirmación explícita, solo sobre lo que el usuario marcó,
y el botón rojo "Cancelar llamadas" las aborta igual que al resto. "Depurar"
además solo puede borrar objetos que la propia auditoría marcó como sin uso,
y como máximo el límite por sesión que fija el usuario (lotes que son prefijos
del orden por dependencias; ver `planificarDepuracion`). La pestaña de tags es
de solo lectura: no existe endpoint de escritura para tags.

## Estructura

```
manifest.json            Manifest V3 (storage + downloads; host permissions opcionales)
popup.html / popup.js    Menú del ícono: dashboard / conexiones
dashboard.html           Dashboard con los seis módulos + consola
connections.html         Alta y gestión de conexiones (también es la options page)
navbar.html              Markup de la barra (compartido por ambas páginas)
css/
  nav.css                Estilos de la barra
  app.css                Estilos del dashboard
js/
  dashboard.js           Shell: cablea UI con módulos (único registro de módulos)
  connections.js         Lógica de la página de conexiones
  lib/
    panApi.js            Cliente XML API — candado de lectura (una excepción: Custom Reports)
    panRestApi.js        Cliente REST — única escritura: reglas -AppID y borrado de objetos; sin commit
    scmApi.js            Cliente de SCM Posture API (lista de hosts; credenciales solo en memoria)
    auditEngine.js       Análisis puro del XML (sin red, sin UI)
    bpaReport.js         BPA: lectura de best_practices, resumen y reporte HTML (puro)
    bpaExcel.js          BPA: Excel de 11 hojas y resolución de Security Profile Groups
    bpaLocal.js          BPA: evaluación local de 45 checks sobre el XML (puro)
    xlsxWriter.js        Generador de .xlsx sin dependencias (zip STORE + XML)
    xmlUtils.js          Ayudas DOMParser
    store.js             Persistencia de conexiones (solo API keys) e historial de depuracion
    util.js              Concurrencia, CSV, descargas, rutas por fecha
    navbar.js            Inyección de navbar + contador en vivo
  modules/
    apikeys.js           Generación masiva de API keys (cuadrícula + CSV)
    certificados.js      Control de vencimiento (firewall, vsys y Panorama)
    audit.js             Módulo de auditoría
    depuracion.js        Borrado de objetos sin uso (orden seguro, pre-chequeo, lotes)
    backups.js           Módulo de backups
    hardening.js         Módulo de hardening App-ID
    bestpractices.js     Best Practices: orígenes JSON, SCM y local; descargas
```

### Agregar un módulo nuevo

1. Crear `js/modules/<nombre>.js` que exporte una función
   `(config, log, onProgreso) => Promise`.
2. Usar solo `js/lib/panApi.js` para hablar con el equipo — no reimplementar
   keygen ni fetch propios (el candado de solo lectura vive ahí). Si el módulo
   necesita otro destino, crear una capa aparte con su propia lista de hosts,
   como `scmApi.js`.
3. Agregar la sección en `dashboard.html` y cablearla en `js/dashboard.js`.

## Notas técnicas heredadas (trampas conocidas)

1. **`chrome.permissions.request()` exige gesto de usuario vivo.** Se invoca
   en `connections.js` dentro del handler del clic, antes de cualquier
   `await`. No mover esa llamada.
2. **`type=export` va por GET, no POST.** El endpoint no acepta POST de forma
   consistente entre versiones de PAN-OS (verificado en producción por el
   módulo de backups de v0.1). Todo lo demás va por POST con la key en el
   cuerpo, fuera de la URL.
3. Detección de error en export: solo se inspeccionan respuestas < 4 KB; una
   config válida se devuelve tal cual.
4. Las consultas de log son asíncronas (job + poll hasta `FIN`); en v0.2 van
   por POST. Si algún equipo con PAN-OS antiguo rechazara el POST del log
   API, cambiar `queryLogs` a GET como hacía v0.1.

## Best Practices: decisiones y trampas

1. **Un solo formato para los tres orígenes.** El JSON de SCM, el que ya tiene
   el usuario y la evaluación local terminan en `best_practices`. Por eso
   `bpaReport.js` y `bpaExcel.js` no saben de dónde vino el dato; la evaluación
   local solo marca `information.origen = "local"` para que los reportes lo
   digan.
2. **Port del script Python de BPA original.** El Excel se verificó celda por celda
   contra el `build()` del script Python original (ejecutado con un openpyxl
   que registra cada valor). Las diferencias son intencionales: marca neutral y
   "Sí (grupo)" en Perfiles cuando se aporta el XML.
3. **El `.xlsx` va sin comprimir (zip STORE).** Evita implementar deflate. Las
   fórmulas (`COUNTIFS` sobre la hoja Detalle) llevan su valor precalculado y
   el libro pide recalcular al abrir: Excel recalcula, pero LibreOffice por
   defecto muestra el valor guardado, así que ese valor tiene que ser exacto.
4. **Subida a SCM: XML sin comprimir con `Content-Encoding: gzip`.** La
   documentación pide gzip, pero hoy el endpoint espera el XML crudo y la firma
   del URL incluye ese header (con gzip real el BPA termina en `FAILED`). Ver
   <https://github.com/PaloAltoNetworks/pan.dev/issues/1327>. Si Palo Alto lo
   corrige, probar sin el header.
5. **La espera de SCM no tiene tope** y toma la señal de cancelación una sola
   vez (misma lección que v0.3.1). Renueva el token si vence, pero un 401 con
   un token recién emitido se trata como falta de permiso, no como
   vencimiento, para no entrar en bucle.
6. **Evaluación local en templates:** un valor ausente es "no aplica", no
   falla. En Panorama, un device-group solo se evalúa en las reglas por defecto
   que sobrescribe y hereda el descifrado de shared.
7. **`chrome.permissions.request()` para SCM** se llama en el handler del
   submit antes de cualquier otro `await`, por la misma razón que en
   Conexiones.

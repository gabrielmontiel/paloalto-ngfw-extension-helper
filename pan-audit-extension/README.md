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

Dos capas de red, cada una con su propia garantía:

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

Las dos operaciones de escritura ("Clonar y ajustar" y "Depurar") solo
corren tras una confirmación explícita, solo sobre lo que el usuario marcó,
y el botón rojo "Cancelar llamadas" las aborta igual que al resto. "Depurar"
además solo puede borrar objetos que la propia auditoría marcó como sin uso.

## Estructura

```
manifest.json            Manifest V3 (storage + downloads; host permissions opcionales)
popup.html / popup.js    Menú del ícono: dashboard / conexiones
dashboard.html           Dashboard con los cinco módulos + consola
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
    auditEngine.js       Análisis puro del XML (sin red, sin UI)
    xmlUtils.js          Ayudas DOMParser
    store.js             Persistencia de conexiones (solo API keys)
    util.js              Concurrencia, CSV, descargas, rutas por fecha
    navbar.js            Inyección de navbar + contador en vivo
  modules/
    apikeys.js           Generación masiva de API keys (cuadrícula + CSV)
    certificados.js      Control de vencimiento (firewall, vsys y Panorama)
    audit.js             Módulo de auditoría
    depuracion.js        Borrado de objetos sin uso (orden seguro + pre-chequeo)
    backups.js           Módulo de backups
    hardening.js         Módulo de hardening App-ID
```

### Agregar un módulo nuevo

1. Crear `js/modules/<nombre>.js` que exporte una función
   `(config, log, onProgreso) => Promise`.
2. Usar solo `js/lib/panApi.js` para la red — no reimplementar keygen ni
   fetch propios (el candado de solo lectura vive ahí).
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

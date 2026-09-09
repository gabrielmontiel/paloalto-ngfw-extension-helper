# Historial de versiones

Notas de cada versión de PAN Helper. Para saber qué hace la herramienta y
cómo se usa, ver el [README](README.md).

## Novedades de v0.2.9 (sobre v0.2.8)

Módulo nuevo: **control de vencimiento de certificados** (port de
`control-vencimiento-certificados/`). Revisa los equipos marcados y agrupa
sus certificados por urgencia — **vencido / crítico / próximo / vigente**—
con los días restantes, umbrales configurables y exportación a CSV.

Funciona en firewall (compartidos, y por cada vsys si es multi-vsys) y en
Panorama (templates más los certificados del propio Panorama). Solo lectura.

Ver la sección **Certificados** para los tres errores del script original que
se corrigieron al portarlo.

En la capa compartida: `getSystemInfo()` devuelve ahora `multiVsys`, `op()`
acepta acotar el comando a un vsys, y se añadió `listarNombres()` para leer
listas de atributos por XML API — esto reemplaza la llamada REST con versión
hardcodeada (`/restapi/v10.2/Panorama/Templates`) del script original, que
solo funcionaba en PAN-OS 10.2.

## Novedades de v0.2.8 (sobre v0.2.7)

Versión de endurecimiento: sin funcionalidad nueva, solo correcciones de
seguridad encontradas en una revisión del código.

- **El candado ya no admite traversal.** La excepción abierta en v0.2.6 para
  guardar Custom Reports terminaba en `(\/.*)?`, que dejaba pasar
  `/config/shared/reports/../address`. Con un motor XPath que resuelva `..`,
  un `action=set` habría alcanzado objetos o reglas — justo lo que el candado
  promete impedir. Ahora el tramo final solo admite segmentos con forma de
  nodo, y se rechazan `..`, `.`, `|`, `//` y llamadas a función.
- **Saneamiento de valores interpolados en XPath.** El campo Vsys entraba sin
  filtrar en `entry[@name='…']`: una comilla rompía la consulta y permitía
  reescribir la ruta. `sanearValorXpath()` se aplica ahora al vsys y al
  nombre del reporte.
- **La API key ya no viaja en la URL al hacer backups.** `exportFile()`
  intenta primero POST con la key en el cuerpo; hasta v0.2.7 iba siempre por
  GET, dejando la key en el log del servidor web del propio equipo y en
  cualquier proxy que intercepte TLS. Se conserva GET como respaldo —el
  endpoint no acepta POST en todas las versiones de PAN-OS— y la caída
  cubre tanto el rechazo HTTP como un 200 con XML de error.
- **Eliminado el código muerto** que el manifest no cargaba: `lib/` (6
  archivos), `options.html`/`options.js`, `dashboard.js` y `dashboard.css`
  de raíz, y `nav.css`. Dos importaban: `lib/panApi.js` exponía
  `setConfigNode` **sin candado alguno**, y `lib/policyGenerator.js` era el
  Policy Optimizer retirado a propósito. Siguen recuperables desde el
  historial de git.

### Lo que la revisión NO encontró

Sin credenciales ni secretos en el código. Sin XSS explotable: de los 17
puntos donde se inserta HTML, los que no escapan reciben valores de
conjuntos cerrados del propio motor (`address`/`service`, `valor`/`nombre`,
`high`/`medium`/`low`/`info`); todo lo que viene del firewall pasa por
`escapeHtml`. Sin `eval`, `new Function` ni manejadores inline. La
contraseña solo existe en tránsito y se limpia del DOM al terminar.

### Riesgos aceptados (inherentes al diseño)

- Las API keys se guardan en `chrome.storage.local` en texto plano.
- El CSV de API keys y el XML crudo de configuración quedan en Descargas sin
  protección.
- `optional_host_permissions: https://*/*` es amplio por necesidad (firewalls
  de clientes arbitrarios); el permiso real se concede por host en tiempo de
  ejecución.

## Novedades de v0.2.7 (sobre v0.2.6)

Módulo nuevo: **generación masiva de API keys** (port de
`generador-apikeys-masivo/api-keys_concurrente.py`). Obtiene la API key de
varios equipos a la vez y, con ella, su hostname, serial, modelo y versión;
el resultado se descarga como CSV para inventario.

- **Cuadrícula de credenciales.** La entrada es una tabla editable tipo hoja
  de cálculo: pegas el rango desde Excel (Ctrl+V) y se rellena sola, o
  escribes directamente en las celdas. Pegar con fila de cabecera reemplaza
  la cuadrícula y usa esa fila para ordenar las columnas; pegar sin cabecera
  rellena posicionalmente desde la celda enfocada, como haría Excel. Al
  escribir en la última fila aparece otra, y cada fila tiene su `×`.
- **Todas las filas se cargan**, incluidas las incompletas: quedan visibles
  para completarlas ahí mismo en vez de desaparecer, y el resumen las cuenta
  aparte (`2 equipo(s) listo(s) · 1 fila(s) incompleta(s)`). También detecta
  repetidos por host + usuario.
- **Cargar CSV** vuelca el archivo a la cuadrícula, así también queda
  revisable antes de ejecutar. **Descargar plantilla** genera un CSV de
  ejemplo con valores obviamente falsos.

### Diferencias deliberadas con el script original

| | Script Python | Extensión |
|---|---|---|
| Credenciales | `PA_PASS.xlsx` en disco, texto plano | pegadas, nunca tocan el disco |
| `keygen` | contraseña **en la URL** | en el cuerpo del POST |
| CSV de salida | arrastra la columna `Pass` | sin contraseñas |
| Concurrencia | `ThreadPoolExecutor` sin límite | acotada a 4 |
| Fallos de certificado | mezclados con el resto | agrupados, con enlaces para aceptarlos |

La API key **no se muestra en pantalla**: va solo al CSV, para poder
compartir pantalla o tomar captura del resultado sin exponer credenciales.
Tampoco se guarda como conexión en la extensión. Al terminar, la cuadrícula
y el campo de contraseña se vacían.

**El CSV resultante es material sensible**: una API key de PAN-OS da el mismo
acceso que la credencial. La interfaz lo advierte.

### Limitación operativa

Chrome exige que el certificado de cada host esté aceptado **antes** de poder
consultarlo, y una extensión no puede saltarse esa advertencia como hacía el
`verify=False` del script. Con equipos nuevos, la primera corrida sirve sobre
todo para obtener la lista de los que fallan; tras aceptar sus certificados
en una pestaña, la segunda sale limpia.

## Novedades de v0.2.6 (sobre v0.2.5)

El módulo de hardening App-ID puede obtener las aplicaciones desde un
**Custom Report** (`trsum`), además de la vía de logs que ya existía. Un
selector **Fuente de datos** elige entre las dos.

- **Generar el reporte con las políticas indicadas** (modo por defecto). La
  extensión arma la definición filtrando por los nombres que escribas
  (`(rule eq 'p1') or (rule eq 'p2')`), la ejecuta y lee el resultado, que
  alimenta la misma tabla con checkboxes y el botón **Clonar y ajustar**.
  Por defecto **no escribe nada en el equipo**: el reporte se corre *ad hoc*,
  lo que no requiere ni guardado ni commit.
- **Guardar también la definición** (casilla opcional). Persiste el reporte
  en la candidate config para que aparezca en *Monitor > Manage Custom
  Reports*. Pide confirmación explícita y avisa de que el commit es manual.
- **Reutilizar un reporte ya creado.** Lee su definición, la ejecuta *ad hoc*
  y nunca la modifica. El botón **Listar** enumera los del equipo.
- **Ver comandos SET** genera los comandos CLI equivalentes, por si prefieres
  crear el reporte a mano en modo `configure`.
- Validaciones: `rule` y `app` en el `aggregate-by` son obligatorios para
  poder atribuir el tráfico por política — se avisa antes de ejecutar si
  faltan y se falla con un mensaje accionable si las filas no traen columna
  de regla. Se aceptan alias de columnas (`Rule`/`Application`).

### El candado, ahora con una excepción

Guardar la definición implica un `config action=set`, así que
`verificarSoloLectura()` deja de ser un "no" absoluto. La excepción es
quirúrgica: solo `set`, y solo si el xpath cae dentro de un contenedor de
reports (`/config/shared/reports` o el equivalente por vsys). Siguen
bloqueados `set` sobre objetos y reglas, sobre `/config/shared` a secas,
sobre xpaths que solo empiezan parecido (`/config/shared/reportsfoo`),
`delete` incluso dentro de reports, y por supuesto `commit`. Hay pruebas
para cada uno de esos casos.

### Compromiso entre fuentes

| | Logs (iterativo) | Custom Report |
|---|---|---|
| Exhaustividad | total | limitada por el `topn` |
| Velocidad | lenta | rápida (datos ya agregados) |
| Periodo | según retention de logs | largo (90 días) sin problema |

El `topn` por defecto subió a 500 (el ejemplo del CLI usa 100, que se queda
corto al analizar varias políticas a la vez). Para exhaustividad total sobre
pocas reglas, la vía de logs sigue siendo la que no se salta ninguna app.

## Novedades de v0.2.5 (sobre v0.2.4)

Port de `Panorama/analizadorAppId-PanoramaConENV.py`: el módulo de hardening
App-ID ahora funciona **también contra Panorama**, no solo contra firewalls.

- **El formulario se adapta a la conexión.** Si eliges un Panorama, aparecen
  sus campos propios y desaparece el de vsys:
  - **Device group** — dónde viven las políticas a analizar (obligatorio
    para clonar y ajustar).
  - **Rulebase** — pre o post-rulebase, tanto para leer la regla original
    como para crear la clonada (por defecto *post*, igual que el script).
  - **Dispositivos (`device_name`)** — uno por línea, para acotar los logs a
    firewalls concretos. Se traduce al mismo sub-filtro del script: uno solo
    va directo, varios se combinan con `or` dentro de un paréntesis. Si lo
    dejas vacío se consultan los logs de todos los equipos que reportan a
    ese Panorama, y la consola lo advierte (dos device-groups con reglas
    homónimas mezclarían sesiones).
- **REST por device-group**: "Clonar y ajustar" usa
  `location=device-group` y los recursos `SecurityPreRules` /
  `SecurityPostRules` en Panorama, y sigue usando `location=vsys` con
  `SecurityRules` en firewalls. El campo `@device-group` se descarta al
  clonar, como en el script.
- **Merge de aplicaciones nuevas** (portado de `procesar_politica`): si la
  regla con sufijo ya existe, en vez de saltarla se comparan sus
  aplicaciones actuales con las recién descubiertas. Si hay nuevas, se
  actualiza con la unión (`PUT`); si no hay, no se toca. Sirve para volver a
  correr el análisis semanas después y recoger lo que apareció entre tanto.
  El resumen final distingue creadas / actualizadas / sin cambios.
  **La regla original nunca se modifica**: el `PUT` solo se aplica a un
  nombre que termina con el sufijo, y se verifica antes de llamar.
- En Panorama los avisos recuerdan que hacen falta **commit a Panorama +
  push al device-group**, ambos manuales.

Diferencia deliberada con el script de Panorama: sus `ALERT_APPS` son solo
`{insufficient-data, unknown-p2p}`, lo que dejaría `unknown-tcp` y
`unknown-udp` entrar en la regla. Aquí se mantiene el conjunto completo
(`insufficient-data`, `unknown-tcp`, `unknown-udp`, `unknown-p2p`): esas
apps se reportan como alerta y nunca se recomiendan.

## Novedades de v0.2.4 (sobre v0.2.3)

- **"Depurar" en Objetos sin uso.** Cada fila de la pestaña tiene ahora un
  checkbox, con "seleccionar todo" global y uno por sección (address-group,
  service-group, address, service). El botón rojo **Depurar** elimina de la
  **candidate config** solo los objetos marcados, tras un popup que lista
  exactamente qué se va a borrar. Sin commit: revisar y confirmar en la GUI
  es obligatorio (y un *revert* allí deshace todo si algo sale mal).
- **Desvinculación automática**: si un objeto marcado pertenece a un grupo
  que *no* vas a borrar, primero se le quita del grupo (`PUT`) y después se
  elimina. Sin eso el firewall rechazaría el borrado por referencia.
- **Orden seguro de borrado**: cuando el grupo también está marcado no hace
  falta editarlo — se borra el grupo primero y luego sus miembros. El orden
  se calcula por dependencias (contenedor antes que contenido), así que
  también funciona con grupos anidados.
- **Grupos que quedarían vacíos**: PAN-OS no admite un grupo estático sin
  miembros. Si quitar lo marcado dejaría el grupo vacío y el grupo no está
  marcado, esos objetos se omiten indicando que hay que marcar también el
  grupo. Se detecta **antes** de tocar la red y el popup lo advierte.
- El borrado va por REST (`Objects/Addresses`, `AddressGroups`, `Services`,
  `ServiceGroups`) y respeta el ámbito real del objeto (shared, vsys o
  device-group). El guard del cliente REST solo admite `PUT`/`DELETE` sobre
  objetos: **nunca** puede modificar ni borrar una regla.

## Novedades de v0.2.3 (sobre v0.2.2)

- **"Clonar y ajustar"** (Fase 2 de `analizadorAppId-REST.py`, vía REST
  API): la tabla de resultados del hardening ahora tiene un checkbox por
  política; al pulsar el botón, para cada política marcada se clona la regla
  original, se reemplaza `application` por las apps descubiertas (filtrando
  otra vez ruido/alerta, como el script), se crea la regla nueva en la
  **candidate config** y se mueve justo antes de la original. Si la regla ya
  existe, se omite la creación y solo se intenta el move. La versión del
  endpoint REST (`/restapi/vX.Y/`) se deriva sola de la versión de PAN-OS
  guardada en la conexión. Solo firewalls (por vsys); las políticas sin apps
  descubiertas tienen el checkbox deshabilitado.
- **Seleccionar todo**: el checkbox de la cabecera marca de una vez todas
  las políticas *clonables* — las que no aplican (sin apps que configurar)
  quedan siempre fuera. Muestra estado intermedio si la selección es
  parcial, y un contador junto al botón indica cuántas están marcadas y
  cuántas no aplican.
- **Sufijo configurable**: campo editable junto al botón, con `-AppID` por
  defecto y una vista previa del nombre resultante. Se sanea a los
  caracteres que PAN-OS admite en un nombre de regla, y si el nombre
  original + sufijo supera los 63 caracteres, esa política se omite con un
  mensaje claro en vez de dejar que el firewall rechace la escritura.
- **Commit imposible por diseño.** Antes de escribir se pide confirmación
  explícita, y el único archivo capaz de escribir
  (`js/lib/panRestApi.js`) tiene un guard que rechaza cualquier endpoint
  distinto de `Policies/SecurityRules` (crear/leer/move). No existe función,
  endpoint ni parámetro de commit en toda la extensión: el commit se hace
  manualmente en la GUI, previa revisión — obligatorio.
- **Columna "Iteraciones" eliminada de la tabla** de resultados: el usuario
  no la necesita para decidir. El dato sigue visible en la consola (por
  regla) y en el CSV resumen.
- El botón rojo "Cancelar llamadas" también aborta las llamadas REST del
  clonado.

## Novedades de v0.2.2 (sobre v0.2.1)

- **Hardening App-ID: descubrimiento iterativo exhaustivo** (port de
  `analizadorAppId-REST.py`). Antes se tomaba una sola muestra de logs, y si
  el tráfico estaba dominado por unas pocas aplicaciones, las minoritarias
  quedaban por fuera. Ahora se consulta por **tandas de 1000 logs** negando
  en la query las apps ya conocidas (`(app neq 'x') and (app neq 'y')...`)
  hasta que una tanda llega vacía o sin apps nuevas — cada iteración solo
  puede traer aplicaciones aún no vistas. Máximo 100 iteraciones por regla;
  las reglas se procesan en secuencia, como el script original.
- Ruido y alerta igual que el script: `incomplete` se niega desde la primera
  tanda y nunca se recomienda; `insufficient-data` y `unknown-*` se reportan
  aparte como alerta y nunca se recomiendan.
- **Checkbox "Descargar CSV resumen"**: decides si al finalizar se descarga
  el CSV (columnas Politica, Total Apps, Aplicaciones Recomendadas, Apps
  Alerta, Iteraciones, Timestamp) o si los resultados quedan solo en
  pantalla.
- Lo que el script hacía como Fase 2 (crear la regla `-AppID` y moverla via
  REST) **no se porta**: la extensión es de solo lectura. El entregable es
  la lista de apps por regla.

## Novedades de v0.2.1 (sobre v0.2)

- **Objetos sin uso: evaluación en todo el firewall.** El uso ya no se mide
  solo contra el rulebase de security: se evalúan también NAT (incluidas las
  direcciones traducidas), decryption, QoS, PBF, authentication, DoS,
  application-override, SD-WAN y tunnel-inspect con la misma semántica de
  ámbitos y cascada de grupos; y como red de seguridad, un índice genérico
  de toda la config marca como "en uso" cualquier objeto cuyo nombre
  aparezca en otra parte (virtual routers, rutas estáticas, VPN/IKE,
  GlobalProtect, interfaces...). Lo que queda listado como "sin uso" no
  aparece en ningún otro lado del firewall — seguro de depurar. El barrido
  genérico compara por nombre exacto y sin ámbitos, a propósito: ante la
  duda, no recomienda borrar.
- **Objetos duplicados: secciones + estado de uso.** La pestaña usa el mismo
  patrón de índice clicable y secciones que "Objetos sin uso" (por criterio
  y tipo), y cada objeto duplicado lleva su insignia **en uso** / **sin
  uso** (la misma evaluación de arriba) para decidir cuál de los duplicados
  se depura y cuál se conserva.

- **Nueva pestaña "Objetos duplicados"** en Auditoría, con dos criterios:
  *por valor* (objetos distintos con el mismo contenido — misma IP/red/FQDN
  o mismo protocolo/puerto — candidatos a consolidarse) y *por nombre* (el
  mismo nombre definido en varios ámbitos, donde el más cercano tapa al
  heredado).
- **Corregido:** los services miembros de un service-group en uso se
  marcaban como sin uso. Los service-groups llevan sus miembros en
  `<members>`, no en `<static>` como los address-groups; ahora se leen
  ambos (bug heredado de pan-audit-extension).
- **Corregido:** al colapsar el menú se rompía todo el layout (la grilla
  seguía definiendo 3 columnas con el menú fuera del flujo, y el contenido
  caía en la columna de 18px).
- **Corregido:** el botón "Auditar" quedaba con texto blanco sobre fondo
  blanco (una regla más específica de la barra de controles pisaba el fondo
  azul de `.primario`).

- **Menú de módulos desplegable.** La franja `«` / `»` entre el menú y el
  contenido lo oculta lateralmente para ampliar la zona de trabajo. El estado
  se recuerda entre sesiones (`localStorage`).
- **Botón rojo "Cancelar llamadas"** en la cabecera del Registro. Aborta de
  inmediato toda llamada al firewall en vuelo — fetch en curso y esperas de
  polling de logs — de cualquier módulo (auditoría, backups, hardening). La
  ejecución termina con *"Operación cancelada por el usuario"* y los botones
  se rehabilitan; las llamadas siguientes funcionan con normalidad.
- **Objetos sin uso: índice por tipo.** Antes de las tablas hay chips
  clicables (`address-group`, `service-group`, `address`, `service`) con el
  conteo de cada tipo; al hacer clic se salta a esa sección. El motivo por
  fila se resumió (p. ej. *"Sin uso porque el address-group 'X' al que
  pertenece tampoco se usa."*) y la explicación del orden de eliminación
  aparece una sola vez como nota de la pestaña.

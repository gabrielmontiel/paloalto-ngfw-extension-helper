# PAN Helper

Extensión de navegador para operar y auditar firewalls **Palo Alto PAN-OS** y
**Panorama**. Todo corre dentro de Chrome: no hay servidor, no hay Python que
instalar y ningún dato sale de tu equipo salvo hacia el firewall que tú
indicas. La única excepción es opcional y explícita: el Best Practice
Assessment oficial, que sube la configuración a Strata Cloud Manager solo si
eliges ese origen y lo confirmas.

Nació de un conjunto de scripts de Python que había que ejecutar a mano, con
las credenciales en un Excel y la API key escrita en el propio código. Aquí
esas tareas viven en una interfaz, cada ingeniero usa su propia credencial y
la herramienta **no puede hacer commit**.

---

## Qué hace

| Módulo | Para qué sirve |
|---|---|
| **Auditoría** | Encuentra reglas deshabilitadas, objetos sin uso, objetos duplicados, reglas que se tapan entre sí y malas prácticas. Permite depurar los objetos que sobran. |
| **Backups** | Descarga configuración, device-state y stats dump de varios equipos, organizados por fecha. |
| **Hardening App-ID** | Descubre qué aplicaciones usa realmente cada regla y crea la versión endurecida de la política. |
| **API Keys** | Obtiene la API key de muchos equipos a la vez y arma un inventario con hostname, serial, modelo y versión. |
| **Certificados** | Revisa los certificados de todo el parque y los agrupa por urgencia de vencimiento. |
| **Best Practices** | Genera el Best Practice Assessment en HTML y Excel: desde un JSON de BPA, pidiéndolo a Strata Cloud Manager, o con una evaluación local de 45 checks que no sale del navegador. |

## El principio que ordena todo: sin commit

La extensión **no puede aplicar cambios en producción.** Puede proponer y
puede escribir en la *candidate config*, pero el commit lo haces tú desde la
GUI del firewall, después de revisar.

Esto no es una promesa: está impuesto en el código. Una única capa de red
(`js/lib/panApi.js`) verifica cada petición antes de tocar la red y rechaza
`commit`, `import` y cualquier escritura de configuración salvo una excepción
acotada por xpath. Las operaciones que sí escriben —clonar reglas, depurar
objetos— piden confirmación explícita y solo actúan sobre lo que marcaste.

**En la práctica:** puedes auditar el firewall de un cliente en producción sin
que exista la posibilidad técnica de modificarlo.

---

## Instalación

1. Abre `chrome://extensions`
2. Activa **Modo de desarrollador** (arriba a la derecha)
3. **Cargar descomprimida** → selecciona la carpeta `pan-audit-extension`
4. Clic en el ícono → **Abrir dashboard**

> **Nota:** requiere Modo de desarrollador, que algunas organizaciones
> bloquean por política. En ese caso hay que empaquetarla y desplegarla por
> política de grupo.

## Antes del primer uso: aceptar el certificado

Los firewalls usan certificado autofirmado. Chrome bloquea las peticiones a un
host cuyo certificado no ha sido aceptado, y una extensión **no puede saltarse
esa advertencia** (es el equivalente al `verify=False` de los scripts, que en
el navegador no existe).

Por cada equipo nuevo, una sola vez:

1. Abre `https://<ip-del-equipo>` en una pestaña normal
2. **Configuración avanzada → Acceder a \<ip\> (no seguro)**
3. Vuelve a la extensión

Si no lo haces, verás un error de conexión que lo indica.

## Crear una conexión

En **Conexiones**, ingresa etiqueta, IP, usuario y contraseña. La extensión
cambia la credencial por una API key (`type=keygen`) y **descarta la
contraseña**: solo guarda la key. A partir de ahí, todos los módulos la
reutilizan y no vuelves a escribir credenciales.

Chrome pedirá permiso para ese host concreto la primera vez.

## Permisos necesarios en el equipo

La cuenta necesita un **Admin Role Profile** con acceso XML API a:

| Para usar | Necesita |
|---|---|
| Auditoría, Backups, Certificados | **Configuration** (lectura), **Operational Requests** |
| Hardening App-ID | además **Log** y **Report** |
| Best Practices desde una conexión | **Configuration** (lectura), **Operational Requests** |
| Clonar y ajustar | además REST → Policies → Security Rules (escritura) |
| Depurar objetos | además REST → Objects (escritura) |

Si solo vas a auditar y respaldar, **una cuenta de solo lectura basta**.

---

# Uso

## Auditoría

Elige una conexión, decide si analizar la **running config** (lo activo) o la
**candidate** (lo que está en staging sin commit), y pulsa **Auditar**. La
configuración se descarga y se analiza entera en tu navegador.

Seis pestañas de resultados:

- **Reglas deshabilitadas** — toda regla con `disabled = yes`.
- **Objetos sin uso** — address, services y grupos que no aparecen en ninguna
  política *ni en el resto de la configuración*. Ver más abajo.
- **Objetos duplicados** — mismo contenido con distinto nombre, o mismo nombre
  en varios ámbitos.
- **Posibles sombras** — reglas que quedan inalcanzables por una anterior.
- **Buenas prácticas** — `any` en reglas allow, sin perfil de seguridad, sin
  log, sin tags.
- **Tags** — tags sin uso, referenciados sin definir, duplicados (mismo
  nombre en varios ámbitos o solo distinto en mayúsculas), inventario con su
  uso en reglas, objetos y filtros de address-groups dinámicos, y qué
  porcentaje de las reglas de security lleva tag. Solo lectura.

Exporta los hallazgos a JSON o CSV, o el XML crudo de la configuración.

### Ejemplo: depurar objetos sin uso

El caso típico tras años de acumulación.

1. **Auditar** → pestaña **Objetos sin uso**
2. Los chips de arriba (`address-group 4`, `address 37`…) saltan a cada
   sección. El orden es el **orden seguro de eliminación**: grupos primero.
3. Marca lo que quieras eliminar y ajusta **Máx. borrados por sesión**
   (100 por defecto)
4. Pulsa **Depurar**. El popup lista exactamente qué se va a borrar en esta
   sesión y cuántos quedan pendientes. Confirma.
5. Revisa el **Balance de depuración** y, si quieres, **Recontar desde la
   candidate** para verificarlo contra el equipo
6. Pulsa **Depurar** otra vez para el siguiente lote; lo pendiente sigue marcado
7. **Revisa en la GUI del firewall y haz commit tú**

Qué resuelve por ti:

- Si un objeto pertenece a un grupo que **no** vas a borrar, primero lo quita
  del grupo y después lo elimina. Sin eso el firewall rechaza el borrado.
- Si el grupo también está marcado, lo borra antes que sus miembros —
  calculando el orden por dependencias, así que funciona con grupos anidados.
- Si quitar un objeto dejaría un grupo estático vacío (PAN-OS no lo admite),
  lo omite y te dice que marques también el grupo.
- Reparte la selección en **lotes**: borrar más de ~200 objetos de una vez ha
  llegado a tumbar el firewall. Cada lote respeta el orden seguro, y el popup
  avisa si pones un máximo por encima de 200.
- Lleva el **balance**: objetos en la config y sin uso antes y después de la
  sesión, y cuánto llevas depurado en ese equipo (historial local por equipo,
  con cada sesión). Solo cuenta lo escrito en la candidate: un revert en la
  GUI no se refleja en el historial.

> **Qué significa "sin uso" aquí:** se verifica contra security, NAT
> (incluidas direcciones traducidas), decryption, QoS, PBF, authentication,
> DoS, SD-WAN, tunnel-inspect, la pertenencia recursiva a grupos, y el resto
> de la configuración —virtual routers, rutas estáticas, VPN, GlobalProtect—.
> Lo que aparece listado no está en ningún otro lado del firewall.

## Backups

Marca los equipos y qué artefactos descargar. Hasta 4 en paralelo.

```
Descargas/PAN-Helper/2026/Septiembre/9/
    PA-backup_FW-SEDE.xml           (configuración)
    PA-DeviceState_FW-SEDE.tgz      (device state)
    PA-StatsDump_FW-SEDE.tar.gz     (stats dump)
```

El **stats dump** es el archivo que pide el soporte de Palo Alto. A
diferencia de los otros dos, el equipo lo genera como tarea: la extensión
lanza el trabajo, espera mostrando el avance y recoge el archivo cuando
termina. Viene desmarcado porque puede tardar varios minutos.

Si la tarea falla en el equipo (por ejemplo, sin espacio en disco), se
reporta el motivo en vez de descargar un archivo corrupto.

## Hardening App-ID

Reemplaza `application = any` por las aplicaciones que la regla usa de verdad.

**Dos fuentes de datos**, según lo que necesites:

| | Logs (iterativo) | Custom Report |
|---|---|---|
| Exhaustividad | total, no se escapa ninguna app | limitada por el `topn` |
| Velocidad | lenta | rápida (datos ya agregados) |
| Periodo | según el retention de logs | largo (90 días) sin problema |

La vía de **logs** consulta en tandas de 1000, negando en cada iteración las
aplicaciones ya vistas, hasta que no aparecen nuevas. La de **Custom Report**
arma un reporte `trsum` agregado por regla y aplicación, y lo ejecuta.

### Ejemplo: endurecer cinco reglas

1. Elige la conexión. Si es un **Panorama**, aparecen sus campos: device
   group, pre/post-rulebase y los dispositivos para acotar los logs.
2. Escribe los nombres de las políticas, uno por línea (o carga un CSV con
   columna `Rule`).
3. **Analizar.** Al terminar tienes la tabla con las aplicaciones encontradas
   por política.
4. Marca las que quieras endurecer, ajusta el **sufijo** si hace falta
   (`-AppID` por defecto) y pulsa **Clonar y ajustar**.
5. Se crea `<Política>-AppID` en la candidate config, clonada de la original
   con el `application` reemplazado, y se mueve justo antes de la original.
   **La regla original nunca se toca.**
6. Revisa y haz commit tú. En Panorama, además el push al device group.

> Si vuelves a correr el análisis semanas después y la regla `-AppID` ya
> existe, no la duplica: compara y le **agrega solo las aplicaciones nuevas**.

Las aplicaciones de baja visibilidad (`unknown-tcp`, `unknown-udp`,
`unknown-p2p`, `insufficient-data`) se reportan aparte y **nunca** entran en
la regla: requieren revisión manual antes de cerrar la política.

## API Keys

Para levantar el inventario de un cliente nuevo.

La entrada es una **cuadrícula editable**: seleccionas el rango en tu Excel,
Ctrl+C, Ctrl+V y se rellena sola. También puedes escribir directamente en las
celdas o cargar un CSV.

```
   Cliente | IP o FQDN | Usuario | Contraseña
 1  ACME   | 10.0.0.1  | admin   | ••••••••     ×
 2  ACME   | 10.0.0.2  | admin   | ••••••••     ×
 3         |           |         |              ×

                        2 equipo(s) listo(s)
```

Las columnas pueden ir **en cualquier orden** — se detectan por el nombre de
la cabecera, y se aceptan variantes (`Hostname`, `Usuario`, `Password`…). Las
filas incompletas se cargan igual, para que las completes ahí mismo.

Al ejecutar, obtiene la API key de cada equipo y con ella su hostname, serial,
modelo y versión. Salida:

```
Descargas/PAN-Helper/apikeys/ApiKeys_202609091430.csv
```

> **El CSV es material sensible**: una API key de PAN-OS da el mismo acceso
> que la credencial. La API key no se muestra en pantalla ni se guarda en la
> extensión — va únicamente a ese archivo.
>
> Las contraseñas nunca tocan el disco: se usan una vez y se limpian de la
> pantalla al terminar.

## Certificados

Marca los equipos y pulsa **Revisar certificados**. Los agrupa por urgencia:

```
[1 Vencido]  [3 Critico]  [1 Proximo]  [1 Vigente]

Estado    Dias  Equipo    Ambito             Certificado     Expira
Vencido   -12   FW-SEDE   n/a                wildcard-corp   Aug 28 2026
Critico     3   PANO-01   template TPL-Sede  tpl-mgmt        Sep 12 2026
Critico    18   FW-SEDE   n/a                gp-portal       Sep 27 2026
Proximo    75   FW-SEDE   n/a                ssl-decrypt     Nov 23 2026
```

Los umbrales (30 y 90 días) son configurables. En un firewall consulta los
compartidos y, si es multi-vsys, los de cada vsys; en Panorama recorre los
templates más los del propio Panorama.

## Best Practices

Genera el reporte de buenas prácticas en **HTML** (dashboard autocontenido,
para revisar en el navegador o adjuntar a un correo) y en **Excel** (Resumen,
Hallazgos, Adopción de seguridad, Reglas, BP Mode con gráfico de radar,
Decryption, Certificados, Zonas, Perfiles, Plataforma y Detalle). Tres
orígenes, un mismo reporte:

| Origen | Qué necesita | ¿Sale la configuración del equipo? |
|---|---|---|
| **JSON de BPA existente** | el JSON que ya bajaste de Strata Cloud Manager | No |
| **Palo Alto SCM Posture API** | un service account de SCM y la running config | **Sí, a la nube de Palo Alto** |
| **Evaluación local** | la running config | No |

La running config se toma de una **conexión guardada** o de un
`running-config.xml` (Device > Setup > Operations > Export named
configuration snapshot).

```
Descargas/PAN-Helper/best-practices/
    BPA_ACME_202609151430.html
    BPA_ACME_202609151430.xlsx
    BPA_ACME_202609151430.json      (solo origen SCM: el resultado crudo)
```

### JSON de BPA existente

Carga el JSON y, opcionalmente, la configuración del mismo equipo: desde su
**conexión guardada** o desde un `running-config.xml`. El JSON del BPA no trae
la definición de los **Security Profile Groups**; sin la configuración, las
reglas que usan grupos quedan fuera de "Habilitado" y "En BP Mode".
Con el XML se resuelven, y en la hoja Perfiles un perfil que solo se usa
dentro de un grupo aparece como **"Sí (grupo)"** en vez de "No".

Si el JSON no trae `adoption` / `adoption_summary` (la API de SCM no siempre
los devuelve), Reglas, Adopción y BP Mode se reconstruyen desde la
configuración de las reglas, y el reporte lo indica.

### Palo Alto SCM Posture API

Pide a Palo Alto el BPA **oficial**: la extensión obtiene un token con tu
service account, sube la configuración, espera el procesamiento (sin tope y
cancelable con **Cancelar llamadas**) y descarga el resultado.

- Hay que **marcar la confirmación** de que la configuración se enviará a
  Palo Alto; sin ella no se hace ninguna petición.
- **Client ID y Client Secret se escriben en cada uso**, viven solo en memoria
  y el secret se borra del formulario al terminar. Nunca se guardan.
- El tipo de equipo (firewall o Panorama) se detecta desde la configuración.
- Por defecto se pide a SCM que **borre la configuración** al procesarla, y se
  guarda el JSON crudo para regenerar reportes sin volver a subir.
- Chrome pide permiso, la primera vez, para `auth.apps.paloaltonetworks.com`,
  `api.sase.paloaltonetworks.com` y `storage.googleapis.com` (donde SCM recibe
  el archivo). Cualquier otro destino se bloquea antes de conectarse.

### Evaluación local

45 checks propios de PAN Helper, evaluados **en el navegador**. **No es el
BPA oficial** —que tiene muchos más controles y datos que no están en el
XML— y el reporte lo dice en su encabezado.

| Grupo | Checks |
|---|---|
| Reglas de seguridad | any/any/any/any, App-ID, service, perfiles de seguridad, log-end, log forwarding, descripción, tags, log en reglas por defecto |
| Descifrado | existe regla decrypt, Decryption profile asignado, TLS ≥ 1.2, bloqueo de certificados vencidos y no confiables |
| Perfiles | Antivirus (reset-both, WildFire), Anti-Spyware (severidades, DNS sinkhole), Vulnerability, URL Filtering (categorías, robo de credenciales), File Blocking, WildFire |
| Zonas | Zone Protection asignado, Packet Buffer Protection, flood protection |
| Administración | Telnet/HTTP, permitted-ip, complejidad de contraseñas (≥ 12), password profiles, cuenta `admin`, superusuarios con auth profile, idle timeout (≤ 15 min), lockout, banner, NTP, SNMP v3, reenvío de logs |
| Actualizaciones | Antivirus, Aplicaciones y Amenazas, WildFire |
| Alta disponibilidad | HA, link/path monitoring, sincronización de configuración |
| Certificados | vencidos, por vencer (≤ 90 días) |

En Panorama recorre shared y los device-groups (reglas y perfiles), los
templates (zonas, administración, actualizaciones, HA) y el propio Panorama.
**En un template, lo que no está definido no cuenta como falla**: se reporta
como "no aplica", porque el firewall puede tenerlo configurado localmente.

---

## Seguridad

| | |
|---|---|
| **Dependencias de terceros** | Ninguna. Sin `package.json`, sin CDN. |
| **Backend / telemetría** | No hay. El tráfico es navegador → firewall, salvo el origen SCM de Best Practices (navegador → Palo Alto), que es opcional y requiere confirmación. |
| **Contraseñas** | Se usan una vez para obtener la API key y se descartan. Nunca se guardan. |
| **Service account de SCM** | Se escribe en cada uso, vive solo en memoria y no se guarda. Nunca aparece en el registro. |
| **API keys** | En `chrome.storage.local`, **en texto plano**. |
| **En tránsito** | Solo HTTPS. La contraseña va en el cuerpo del POST, nunca en la URL. |
| **Permisos** | `storage` y `downloads`. El acceso a cada firewall —y a Strata Cloud Manager, si lo usas— se concede por host en tiempo de ejecución. |
| **Trazabilidad** | Cada acción queda en los logs de PAN-OS con el usuario real del ingeniero. |

### Riesgos que conviene conocer

- Las **API keys guardadas están en texto plano** en el perfil de Chrome.
  Quien tenga acceso a ese perfil puede leerlas. Usa cuentas de solo lectura
  cuando sea posible y no dejes guardadas conexiones de clientes que ya no
  administras.
- Los archivos descargados —CSV de API keys, XML crudo de configuración—
  quedan **sin protección** en tu carpeta de Descargas. El XML de una
  configuración incluye hashes de contraseñas de administradores y material
  criptográfico.
- El origen **SCM** de Best Practices **sube la configuración completa del
  cliente a Palo Alto**. Úsalo solo con autorización del cliente; los otros
  dos orígenes no envían nada.

## Limitaciones conocidas

- Las pestañas de **reglas deshabilitadas, sombras y buenas prácticas**
  analizan solo el rulebase de *security*. (La detección de objetos sin uso sí
  cubre todas las políticas.)
- Los **templates de Panorama no se recorren** en la auditoría de
  configuración — sí en certificados.
- Los **address-groups dinámicos** (por tag) no se resuelven estáticamente,
  así que sus miembros nunca se marcan como sin uso. Es deliberado, para no
  producir falsos positivos.
- La **detección de sombras es heurística**: trata cada resultado como algo a
  verificar, no como veredicto.
- El `topn` del Custom Report **limita la muestra**: una aplicación muy
  minoritaria puede quedar fuera. Para exhaustividad, usa la vía de logs.
- La **evaluación local de Best Practices** solo ve la configuración: no ve
  licencias, versiones de contenido instaladas ni tráfico. Los perfiles
  predefinidos (`default`, `strict`) no están en el XML y no se evalúan. Si una
  zona no define Packet Buffer Protection explícitamente, se reporta "no
  aplica": el valor por defecto depende de la versión de PAN-OS.

## Estado de madurez

**Beta funcional, apta para piloto controlado.** El módulo de backups está
verificado contra equipos reales. El resto está cubierto por pruebas
automatizadas contra firewalls simulados, pero **los caminos de escritura
(clonar, depurar) y el soporte de Panorama no tienen aún rodaje en
producción**. Pruébalos en laboratorio antes de usarlos con un cliente.

**Best Practices** está validado contra el script Python del que proviene
(mismo resultado celda por celda en el Excel) y con configuraciones y
respuestas de SCM simuladas, pero **aún no contra un BPA ni un tenant de SCM
reales**. En particular, conviene confirmar en la primera corrida real el
valor de `device_type` para Panorama y los hosts de SCM.

---

## Documentación adicional

- **[CHANGELOG.md](CHANGELOG.md)** — historial de versiones y qué cambió en cada una.
- **[pan-audit-extension/README.md](pan-audit-extension/README.md)** — decisiones de
  diseño, arquitectura y cómo agregar un módulo nuevo.

## Licencia

MIT. Sin dependencias de terceros, así que no hay obligaciones de
cumplimiento heredadas.

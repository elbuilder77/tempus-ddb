# Gate B2A para Agente DevOps sobre MCP — Blueprint de producto

*Inspirado en el patrón B2A (Bot-to-Agent) de [tempus-ddb](https://github.com/elbuilder77/tempus-ddb), adaptado a un servidor MCP propio para un agente de DevOps que abre PRs en GitHub y manda alertas a Slack.*

## Tagline
Que abrir un PR o mandar una alerta a Slack pase siempre por un permiso firmado, nunca por una tool que el agente pueda invocar directo.

## El problema
El servidor MCP propio expone hoy (o expondrá) tools que abren PRs en GitHub y postean en Slack. Si esas tools llevan directamente el `GITHUB_TOKEN` o el `SLACK_BOT_TOKEN` en el mismo proceso que atiende al agente, cualquier error de razonamiento del agente, o cualquier instrucción inyectada desde un issue o mensaje que el agente esté leyendo, puede traducirse de inmediato en una acción real sin ningún punto de control intermedio.

## La solución
Introducir un gate entre el agente y las tools destructivas/con efecto real:
1. El agente **firma la intención** ("abrir PR con este título/body en este repo", "postear esta alerta en este canal").
2. El **gate** evalúa esa intención contra una política (qué repos, qué canales, qué tipo de PR están permitidos) y emite un **vale de un solo uso**.
3. El **servidor MCP de ejecución** — que sí sostiene `GITHUB_TOKEN` y `SLACK_BOT_TOKEN` — consume el vale y ejecuta la acción real.
4. Se genera un **recibo firmado** por gate y ejecutor por cada PR abierto o alerta enviada.

## Para quién es
Equipos que exponen un servidor MCP propio a un agente de DevOps (o similar) con tools que escriben en sistemas externos (control de versiones, chat, tickets), y quieren que esas tools nunca puedan ejecutarse sin pasar por una autorización verificable.

## Por qué esto y no simplemente "tools con permisos" en el propio servidor MCP
| Dimensión | Tools MCP con checks de permiso inline | Gate B2A delante del servidor MCP de ejecución |
|---|---|---|
| Modelo de confianza | El mismo proceso decide y ejecuta | Decidir y ejecutar están en procesos separados |
| Credenciales | `GITHUB_TOKEN`/`SLACK_BOT_TOKEN` viven junto a la lógica que el agente activa | Viven solo en el servidor de ejecución, nunca alcanzables por el agente |
| Repetición de una acción | Un agente que reintenta puede volver a abrir el mismo PR | El vale ya consumido hace fallar el reintento |
| Evidencia de qué se hizo | Logs del servidor MCP | Recibo firmado, verificable sin confiar en esos logs |

## Componentes mínimos viables
- Servidor MCP "de cara al agente" — expone solo `solicitar_accion` y herramientas de lectura/verificación, nunca `github.create_pull_request` o `slack.post_message` directas.
- Gate de autorización — política de repos/canales permitidos, emite vales.
- Servidor MCP (o proceso) de ejecución — sostiene los tokens reales, consume vales, ejecuta.
- Recibo verificable por cada PR o alerta.

## Modelo de adopción
Como servidor MCP: exactamente el modelo que ya usa tempus-ddb en su "modo autónomo" — un servidor MCP que solo expone operaciones de autorización/lectura firmadas (nunca tools que acepten rutas de archivos de claves locales en producción), separado del proceso de aprovisionamiento/administración.

## Diferenciación
No es un servidor MCP con "más validación" — es dividir en dos el servidor MCP que hoy imaginan como uno solo: uno que el agente ve (sin poder real) y otro que ejecuta (con poder real, invisible al agente).

## Riesgos y límites conocidos
Este patrón no evita que alguien con acceso directo al servidor de ejecución (fuera del agente) abuse de los tokens; tampoco sustituye una revisión humana de los PRs una vez abiertos. Reduce la superficie de que el propio agente, comprometido o confundido, sea quien tenga el poder de ejecutar directamente.

## Camino de adopción: construir vs. usar tempus-ddb directamente
tempus-ddb ya trae exactamente este caso resuelto de fábrica: un ejecutor de GitHub (`github.create_issue`, `github.create_pull_request`) y un ejecutor de Slack (`slack.post_message`, `slack.send_alert`), además de un modo MCP autónomo documentado (`cookbooks/mcp_cursor_claude_quickstart.md`) que expone solo las operaciones firmadas. Si el equipo ya está dispuesto a depender de un paquete de Python, instalarlo directamente puede ahorrar la construcción de los dos ejecutores desde cero.

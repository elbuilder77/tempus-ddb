# Gate de Pagos B2A para CrewAI — Blueprint de producto

*Inspirado en el patrón B2A (Bot-to-Agent) de [tempus-ddb](https://github.com/elbuilder77/tempus-ddb), adaptado a un equipo de agentes CrewAI que paga proveedores vía Stripe.*

## Tagline
Un peaje criptográfico entre el agente que decide cuánto pagar y el proceso que efectivamente mueve el dinero.

## El problema
Hoy, el agente CrewAI que decide "cuánto pagarle a este proveedor" y el agente que dispara la transferencia real en Stripe comparten, en la práctica, la misma superficie de confianza: si el agente decisor alucina un monto, es engañado por un prompt malicioso en un documento de proveedor, o simplemente tiene un bug, nada estructural le impide llegar hasta la API key de Stripe y ejecutar el cargo. El riesgo no es solo "¿decidió bien el monto?" sino "¿quién puede aprobar y ejecutar al mismo tiempo?".

## La solución
Separar el equipo CrewAI en dos roles con una autorización criptográfica de por medio:
1. El agente decisor **firma una intención** ("pagar $X a proveedor Y por concepto Z"), pero no toca Stripe.
2. Un **gate** evalúa esa intención contra una política firmada (límites por proveedor, techos diarios, moneda permitida) y, si pasa, emite un **vale de un solo uso** que expira en minutos.
3. Un **ejecutor de pagos aislado** — que es el único proceso con la API key real de Stripe — consume el vale y ejecuta el cargo.
4. El resultado produce un **recibo firmado** por el gate y el ejecutor, verificable después por cualquiera sin tener que confiar en los logs de la aplicación.

## Para quién es
Equipos que operan flujos CrewAI (o multiagente en general) donde al menos un agente puede iniciar movimientos de dinero, y quieren que ese poder de ejecución nunca resida en el mismo proceso que toma la decisión.

## Por qué esto y no un RBAC/proxy tradicional
| Dimensión | Proxy/RBAC tradicional sobre la tool de Stripe | Gate de Pagos B2A |
|---|---|---|
| Modelo de confianza | Si el rol del agente tiene permiso, el cargo pasa | El agente decisor nunca puede cargar por sí solo, sin importar su rol |
| Credenciales | La tool de Stripe suele vivir en el mismo proceso del agente | La API key vive solo en el ejecutor de pagos, un proceso aparte |
| Repetición de un pago ya autorizado | Un reintento con los mismos parámetros puede volver a pasar | El vale ya fue consumido; un reintento con el mismo vale falla |
| Evidencia | Logs de CrewAI / de la app | Recibo firmado por gate + ejecutor, verificable offline |

## Componentes mínimos viables
- Agente decisor (CrewAI) — firma la intención de pago.
- Gate de autorización — evalúa política de pagos y emite el vale.
- Política de pagos firmada — techos por proveedor, moneda, límite diario.
- Ejecutor de pagos aislado — sostiene la API key de Stripe, consume el vale, ejecuta el cargo.
- Recibo verificable — ata la autorización al resultado del cargo.

## Modelo de adopción
Como sidecar: un pequeño servicio de gate (puede ser un solo proceso local al principio) que corre junto al crew de CrewAI, expuesto solo a los agentes vía una tool custom de "solicitar pago" — nunca vía la tool de Stripe directamente. El ejecutor de pagos puede vivir en ese mismo sidecar o en un proceso separado si se quiere aislamiento más fuerte desde el día uno.

## Diferenciación
No es "agregar un límite de gasto" a la tool existente — es quitarle a esa tool la capacidad de ejecutar por sí sola. La tool de Stripe deja de existir para el agente decisor; solo existe la tool "solicitar pago", que nunca mueve dinero por sí misma.

## Riesgos y límites conocidos
Este patrón no resuelve qué pasa si el ejecutor de pagos mismo es comprometido (sigue siendo el punto que sostiene la credencial real), ni protege contra el borrado del almacén local donde vive el historial de vales consumidos, si ese almacén no tiene su propio respaldo. Es una reducción de superficie, no una garantía absoluta.

## Camino de adopción: construir vs. usar tempus-ddb directamente
Como CrewAI y el ejecutor de pagos aquí descrito están en Python, `pip install tempus-ddb` es una opción real de arranque rápido: ya trae un ejecutor de pagos pluggable (`tempus-payment-executor`) que implementa exactamente el rol de "ejecutor aislado" descrito arriba, con un transporte mock para pruebas y espacio para conectar el cliente real de Stripe en la capa de transporte. Construir desde cero con este blueprint tiene sentido si el equipo quiere su propio modelo de firma o integrarlo como parte de un producto de pagos más grande.

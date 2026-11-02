<div align="center">
  <img src="https://raw.githubusercontent.com/tempus-protocol/tempus-ddb/main/assets/logo.png" alt="Tempus DDB" width="180" />

# Tempus DDB

**Evidencia de que la acción de un agente fue autorizada, y de que ocurrió exactamente como se autorizó.**

Ningún efecto sale sin un permiso firmado y de un solo uso. Todo efecto deja un recibo
firmado. Cualquiera con la clave pública del gate puede verificarlo en el navegador, sin
confiar en nadie.

[**Verificar evidencia ahora →**](https://tempus-protocol.github.io/tempus-ddb/verify.html) · [Especificación](SPEC.md) · [Referencia completa](docs/REFERENCE.md) · [English](README.md)

</div>

---

## Empieza aquí: verifica un recibo

Alguien te entrega un archivo. Abre el [verificador público](https://tempus-protocol.github.io/tempus-ddb/verify.html),
carga el archivo, pega la clave pública del gate que obtuviste por otro canal y lee el
veredicto. La página es el mismo verificador que la CLI, compilado a WebAssembly: funciona
sin red y nada sale de tu navegador. Pulsa **Load a real sample** para ver un bundle
verificado, y **Load a tampered sample** para ver uno con un campo firmado alterado.

Cada recibo que firma Tempus dice dónde hacerlo: su `verify_url` apunta al verificador
con el identificador de la acción, y cada bundle exportado lleva en el enlace el digest
del bundle, así que enlace y archivo se comprueban entre sí.

```bash
# La misma comprobación desde la terminal, solo con el archivo y la clave pública:
tempus verify-bundle --bundle evidence.json --gate-public-key <64 hex>
```

## Instalación en tres comandos

```bash
python -m pip install tempus-ddb        # wheels precompilados para Python 3.10+, sin Rust
tempus init --allow-all-dev             # clave del gate y base local; allow-all es un atajo de desarrollo
tempus status                           # claves, base, identidades, política, URL del verificador
```

Sin `--allow-all-dev` el gate deniega toda acción hasta que instales una política
firmada (default-deny). Para trabajar sobre el código fuente, ver
[docs/REFERENCE.md](docs/REFERENCE.md#install).

## Tu primera acción verificada

```bash
tempus keygen --output agent.keys.json
tempus keygen --output executor.keys.json
tempus register-agent --alias demo-agent    --agent-keyfile agent.keys.json    --metadata '{"tenant_id":"acme"}'
tempus register-agent --alias demo-executor --agent-keyfile executor.keys.json --metadata '{"tenant_id":"acme"}'

# 1. El agente firma lo que quiere hacer.
AGENT_PUB=$(python -c "import json; print(json.load(open('agent.keys.json'))['public_key'])")
cat > intent.json <<EOF
{"schema_version": "tempus.action-intent.v1", "tenant_id": "acme", "agent_id": "$AGENT_PUB",
 "idempotency_key": "issue-001", "action_type": "github.create_issue", "resource": "acme/widgets",
 "requested_at": $(python -c "import time; print(time.time_ns() // 1000)"),
 "input": {"title": "Rotar la clave de staging"}}
EOF

# 2. El gate evalúa la política y firma un permiso de un solo uso (o una denegación firmada).
tempus request-action --intent intent.json --agent-keyfile agent.keys.json --ttl-seconds 60 > permit.json
AUTH_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['authorization_id'])")
ACTION_ID=$(python -c "import json; print(json.load(open('permit.json'))['authorization']['action_id'])")

# 3. El ejecutor hace el trabajo y firma el resultado; el gate firma el recibo.
cat > outcome.json <<EOF
{"schema_version": "tempus.action-outcome.v1", "authorization_id": "$AUTH_ID",
 "action_id": "$ACTION_ID", "status": "SUCCEEDED", "external_reference": "acme/widgets#17"}
EOF
tempus commit-outcome --authorization-id "$AUTH_ID" --outcome outcome.json --executor-keyfile executor.keys.json > execution.json

# 4. Un archivo para cualquiera: se verifica solo con el archivo y la clave PÚBLICA del gate.
tempus export-bundle --action-id "$ACTION_ID" --out evidence.json --create-checkpoint
GATE_PUB=$(python -c "import json; print(json.load(open('keys.json'))['public_key'])")
tempus verify-bundle --bundle evidence.json --gate-public-key "$GATE_PUB"
```

`export-bundle` imprime el `verify_url` del bundle. Envía `evidence.json` y la clave
pública del gate (nunca el archivo de claves) a quien tenga que comprobarlo; puede abrir
el enlace y cargar el archivo.

## Qué prueba un recibo, y qué no

Un resultado `VERIFIED` significa que cada documento firmado del archivo es byte a byte
lo que firmó el gate cuya clave fijaste, que la intención del agente es la que originó el
permiso, que el resultado del ejecutor es el que cubre el recibo y, con checkpoint, que
los eventos están en el ledger encadenado del gate sin huecos ni retrocesos.

No prueba lo que ningún documento puede probar: que el permiso se usó una sola vez, o
que no ocurrió nada más. El verificador lo lista en `trust.not_checked` en vez de
callarlo. Un documento comprobado contra la misma base de la que salió se reporta como
no independiente. Las reglas están en [SPEC.md](SPEC.md); los ataques considerados, en
[THREAT_MODEL.md](THREAT_MODEL.md).

## Cómo funciona

```text
el agente firma la intención ──► el gate evalúa la política firmada ──► permiso de un uso (ALLOWED | BLOCKED)
                                                                              │
                        el ejecutor guarda la credencial, actúa y firma el resultado
                                                                              │
                        el gate firma el recibo, lo encadena en el ledger y firma checkpoints
                                                                              │
                        cualquiera verifica recibo o bundle con la clave pública del gate (navegador o CLI)
```

- **Falla cerrado.** Sin política instalada, esquema desconocido, clave no registrada o
  revocada, permiso caducado, JSON ambiguo (claves repetidas, números inexactos): el gate
  deniega o rechaza, y firma la denegación.
- **Aislamiento de credenciales.** El agente que pide nunca tiene el token del destino;
  lo tiene el ejecutor mediado, y solo actúa con un permiso sin consumir.
- **Un resultado por permiso.** Un segundo resultado distinto se rechaza; un ejecutor
  que no puede saber si el efecto ocurrió registra `UNKNOWN` y nunca reintenta.
- **Evidencia que un tercero puede comprobar.** Firmas Ed25519, SHA-256 sobre una forma
  canónica, checkpoints firmados sobre el flujo de eventos y un verificador público.

## Python en veinte líneas

```python
import json, time
from tempus_ddb import TempusDDB, gen_keys

for name in ("gate", "agent", "executor"):
    gen_keys(f"{name}.keys.json")
key = lambda name: json.load(open(f"{name}.keys.json"))["public_key"]

gate = TempusDDB("tempus.db", "gate.keys.json")
gate.register_agent(key("gate"), "gate", '{"can_delegate":true}')
gate.register_agent(key("agent"), "agent", "{}")
gate.register_agent(key("executor"), "executor", "{}")
gate.install_allow_all_dev_policy()          # solo desarrollo; install_policy(...) para reglas reales

intent = {"schema_version": "tempus.action-intent.v1", "tenant_id": "acme", "agent_id": key("agent"),
          "idempotency_key": "purchase-001", "action_type": "purchase", "resource": "vendor-api/credits",
          "requested_at": time.time_ns() // 1_000, "input": {"sku": "compute-credits"},
          "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"}}
permit = json.loads(gate.request_action(json.dumps(intent), "agent.keys.json", 60))["authorization"]
assert permit["decision"] == "ALLOWED"

outcome = {"schema_version": "tempus.action-outcome.v1", "authorization_id": permit["authorization_id"],
           "action_id": permit["action_id"], "status": "SUCCEEDED", "external_reference": "vendor-tx-1"}
gate.commit_outcome(permit["authorization_id"], json.dumps(outcome), "executor.keys.json")

bundle = gate.export_bundle(permit["action_id"], None)
print(json.loads(bundle)["verify_url"])      # ábrelo, carga el bundle, pega key("gate")
```

Para agentes y ejecutores remotos usa `request_action_signed` / `commit_outcome_signed`
(firman en local; el gate nunca ve sus claves), o el servidor MCP (`tempus mcp start`).
Hay ejecutores empaquetados para GitHub, webhooks HTTP, Slack y pagos: ver la
[referencia](docs/REFERENCE.md#packaged-mediated-executors).

## El protocolo

Quince contratos `.v1`, especificados en [SPEC.md](SPEC.md) con fixtures de conformidad
en `conformance/evidence/` contra los que se prueban el verificador nativo y el del
navegador. Estables en toda la línea `0.x` ([COMPATIBILITY.md](COMPATIBILITY.md)).

| Documento | Esquema | Lo firma |
|---|---|---|
| Intención del agente | `tempus.action-intent.v1` | agente |
| Permiso | `tempus.authorization-receipt.v1` | gate |
| Resultado de autorización | `tempus.authorization-result.v1` | — (envoltorio) |
| Política | `tempus.policy-bundle.v1` | gate |
| Evidencia de política | `tempus.policy-evidence.v1` | — (digest en el permiso) |
| Registro de identidad | `tempus.agent-registration.v1` | registrador |
| Evento de ciclo de vida | `tempus.identity-lifecycle-event.v1` | gate |
| Resultado del ejecutor | `tempus.action-outcome.v1` | ejecutor |
| Recibo de ejecución | `tempus.execution-receipt.v1` | gate |
| Resultado de ejecución | `tempus.execution-result.v1` | — (envoltorio) |
| Observación del ejecutor | `tempus.executor-observation.v1` | ejecutor |
| Traza de la acción | `tempus.action-trace.v1` | — (envoltorio) |
| Evento del ledger | `tempus.event-stream-event.v1` | — (encadenado por hash) |
| Checkpoint | `tempus.checkpoint.v1` | gate |
| Bundle de evidencia | `tempus.evidence-bundle.v1` | — (contiene los anteriores) |

Los resultados de verificación son `tempus.trace-verification.v1` y
`tempus.checkpoint-verification.v1`.

## Construido sobre Tempus

- **Tempus Guard for GitHub** ([tempus-github-app](https://github.com/tempus-protocol/tempus-github-app)):
  ejecutor GitHub App que solo hace push con permiso y pondrá un check "Verificado por
  Tempus" en cada pull request, enlazando al verificador (0.7).
- **Tempus Guard CLI** ([tempus-guard-cli](https://github.com/tempus-protocol/tempus-guard-cli)):
  el lado cliente de Guard; `tempus guard intent` firma la intención de push desde una rama local.
- **Tempus Advance** ([Tempus-Advance](https://github.com/tempus-protocol/Tempus-Advance)):
  consola hospedada de solo lectura sobre los mismos contratos (0.9).

Comparación con gateways MCP y RBAC: [docs/COMPARISON.md](docs/COMPARISON.md).
Hitos: [ROADMAP.md](ROADMAP.md).

## Frontera de seguridad

Tempus detecta recibos, políticas, evidencias y trazas alteradas o falsificadas; rechaza
actores no registrados o revocados; rechaza peticiones idempotentes en conflicto; e impide
que dos resultados consuman un permiso. Todavía no impide el borrado de toda la base del
gate sin un anclaje externo (0.8), ni el bypass de un agente que conserve una credencial
del destino. Lee [THREAT_MODEL.md](THREAT_MODEL.md) antes de apoyarte en él para acciones
de alto impacto, y [SECURITY.md](SECURITY.md) para reportar una vulnerabilidad.

## Desarrollo

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --all-targets
ruff check . && python -m pytest tests/
bash scripts/build_wasm_verifier.sh && node scripts/test_wasm_verifier.mjs && node scripts/validate_site.mjs
```

Ver [CONTRIBUTING.md](CONTRIBUTING.md). Todo lo demás, de la autoría de políticas y los
ejecutores a los checkpoints, la configuración MCP y el firmador Vault, está en
[docs/REFERENCE.md](docs/REFERENCE.md) (en inglés).

## Licencia

MIT. Ver [LICENSE](LICENSE).

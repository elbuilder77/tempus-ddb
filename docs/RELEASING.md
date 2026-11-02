# Publicar una versión

Este documento describe cómo `.github/workflows/release.yml` construye, firma y
publica Tempus DDB, y cómo comprobar después un artefacto descargado. El
workflow ya existía: generaba un SBOM SPDX, firmaba la procedencia con
`actions/attest-build-provenance` y adjuntaba ese SBOM con `actions/attest-sbom`.
Lo que sigue es el flujo actual, con CycloneDX, el disparo por tag y la
aprobación manual.

Las atestaciones de GitHub Actions son firmas [Sigstore](https://www.sigstore.dev/).
En un repositorio público el certificado sale de la instancia public-good
(Fulcio) y queda registrado en el log de transparencia (Rekor). No hay un
segundo paso con `cosign`: `gh attestation verify` comprueba esa misma firma.

## Disparo

Hay dos formas de arrancar el workflow.

| Evento | Qué hace |
|---|---|
| Push de un tag `v*` (por ejemplo `v0.6.0`) | Construye, prueba y, tras la aprobación, publica. |
| `workflow_dispatch` con `publish` en falso | Construye y prueba el tag indicado. No publica. |
| `workflow_dispatch` con `publish` en verdadero | Igual que un tag: publica solo después de la aprobación. |

El tag tiene que existir y el commit de ese tag tiene que contener este
workflow. El checkout de cada job usa ese tag, no la rama desde la que se
lanzó a mano.

`Cargo.toml` y `pyproject.toml` deben llevar la misma versión, y el tag debe
ser esa versión con el prefijo `v`. Si no coinciden, los jobs de publicación
terminan antes de subir nada.

Un tag que contiene `-` (por ejemplo `v0.6.0-rc.1`) se marca como pre-release
y no queda como «latest». La versión de los manifiestos tiene que ser
exactamente `0.6.0-rc.1`.

El workflow crea la GitHub Release. Por eso ya no escucha el evento
`release: published`: ese evento volvería a lanzar el mismo workflow cuando la
release se crea.

## Qué hace cada fase

Los jobs de construcción no piden aprobación. Sirven para que, antes de
aprobar, se vean en verde las ruedas, el sdist y los tests.

1. **build** y **sdist** generan las ruedas (Linux, Windows y macOS) y el
   sdist con maturin.
2. **test-wheels** instala la rueda construida, no el árbol de fuentes, y
   ejecuta pytest.
3. **cargo-test** ejecuta `cargo test`.
4. **release** espera al environment `release`. Cuando un revisor lo aprueba:
   - comprueba que el tag coincide con las dos versiones;
   - genera el SBOM SPDX 2.3 con `scripts/generate_sbom.py`;
   - genera el CycloneDX 1.5 de Rust con `cargo-cyclonedx` 0.5.9, a partir del
     cierre de dependencias del target del runner (no incluye dev-dependencies);
   - instala la rueda Linux x86_64 en un virtualenv y genera el CycloneDX 1.6
     de Python con `cyclonedx-bom` 7.5.0;
   - firma la procedencia de `dist/*` y de `sbom/*`;
   - adjunta cada SBOM a los artefactos de `dist/` con `actions/attest-sbom`;
   - sube ruedas, sdist y los tres SBOM a la GitHub Release;
   - publica en PyPI por Trusted Publishing (OIDC).
5. **publish-crates** vuelve a esperar al environment `release` y solo corre
   si el job anterior terminó bien. Intercambia el OIDC de GitHub por un token
   de crates.io de corta duración y ejecuta `cargo publish --locked`.

PyPI y crates.io viven en el mismo workflow, en dos jobs. Si crates.io falla,
la Release de GitHub y PyPI no se deshacen: el job de release sigue en verde y
`publish-crates` queda en rojo. Se recupera reejecutando solo ese job, que
pide otra aprobación. Si fallan las ruedas, los SBOM, las atestaciones o PyPI,
el crate no se publica.

`skip-existing: true` hace que un reintento no falle cuando PyPI ya tiene esa
versión. crates.io no admite republicar la misma versión: `cargo publish`
fallará y eso es lo esperado. La siguiente publicación tiene que ser una
versión nueva.

Los dos jobs de publicación piden aprobación por separado. Son dos deployments
del mismo environment.

## Artefactos de la release

Para el tag `vX.Y.Z`:

| Archivo | Contenido |
|---|---|
| `tempus_ddb-X.Y.Z-*.whl` y el sdist | Distribuciones que se publican en PyPI. |
| `tempus-ddb-vX.Y.Z.spdx.json` | Inventario SPDX 2.3 de `Cargo.lock` y de las dependencias declaradas en `pyproject.toml`. |
| `tempus-ddb-vX.Y.Z.rust.cdx.json` | CycloneDX del crate, generado por `cargo-cyclonedx`. |
| `tempus-ddb-vX.Y.Z.python.cdx.json` | CycloneDX del entorno donde se instaló la rueda Linux, sin pip, setuptools ni wheel. |

El SPDX usa `SOURCE_DATE_EPOCH` del commit etiquetado. Los CycloneDX no: si
esa variable está definida, `cargo-cyclonedx` 0.5.9 omite `serialNumber` y
`actions/attest-sbom` rechaza el documento. El número de serie de CycloneDX
cambia en cada ejecución. Hay que verificar el archivo descargado de la
release, no un SBOM regenerado en local.

## Permisos

El workflow solo tiene `contents: read`. El job que firma y publica en PyPI
añade `contents: write`, `id-token: write` y `attestations: write`. El job de
crates.io solo añade `contents: read` e `id-token: write`. Los jobs de build
no reciben un token OIDC.

Todas las actions están fijadas por SHA de commit. `cargo-cyclonedx` está
fijado en 0.5.9 con `--locked` y `cyclonedx-bom` en 7.5.0.

## Verificar con gh attestation verify

Hace falta la [GitHub CLI](https://cli.github.com/) autenticada (`gh auth login`)
y los archivos tal como se descargaron. El `--repo` es el repositorio que
ejecutó el workflow. Hoy ese repositorio es `tempus-protocol/tempus-ddb`.

Sustituye los nombres por los de la release. La procedencia SLSA es el
predicado por defecto:

```bash
gh attestation verify tempus_ddb-X.Y.Z-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl \
  --repo tempus-protocol/tempus-ddb \
  --signer-workflow tempus-protocol/tempus-ddb/.github/workflows/release.yml
```

El mismo comando sirve para el sdist y para cada SBOM, porque esos archivos
también son sujetos de la atestación de procedencia:

```bash
gh attestation verify tempus-ddb-vX.Y.Z.spdx.json \
  --repo tempus-protocol/tempus-ddb \
  --signer-workflow tempus-protocol/tempus-ddb/.github/workflows/release.yml

gh attestation verify tempus-ddb-vX.Y.Z.rust.cdx.json \
  --repo tempus-protocol/tempus-ddb

gh attestation verify tempus-ddb-vX.Y.Z.python.cdx.json \
  --repo tempus-protocol/tempus-ddb
```

Para ver el SBOM que quedó ligado a una rueda, el sujeto es la rueda y el
predicado cambia. SPDX 2.3 usa `https://spdx.dev/Document/v2.3`. Los dos
CycloneDX (Rust y Python) usan el mismo tipo, `https://cyclonedx.org/bom`;
`--format json` muestra los dos predicados.

```bash
gh attestation verify tempus_ddb-X.Y.Z-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl \
  --repo tempus-protocol/tempus-ddb \
  --predicate-type https://slsa.dev/provenance/v1

gh attestation verify tempus_ddb-X.Y.Z-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl \
  --repo tempus-protocol/tempus-ddb \
  --predicate-type https://spdx.dev/Document/v2.3

gh attestation verify tempus_ddb-X.Y.Z-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl \
  --repo tempus-protocol/tempus-ddb \
  --predicate-type https://cyclonedx.org/bom \
  --format json
```

Una verificación correcta identifica el workflow
`.github/workflows/release.yml` y el ref `refs/tags/vX.Y.Z`. Si el archivo se
modificó después de descargarlo, el digest no coincide y `gh` lo rechaza.

## Configuración que este archivo no puede crear

Hay que dejarla hecha antes del primer tag que use este workflow. Si el
environment no tiene revisores obligatorios, GitHub no pausa el job: en cuanto
el environment existe, o se crea vacío en la primera ejecución, la publicación
sigue sola.

1. **Environment `release`** en el repositorio (Settings → Environments):
   - Nombre exacto: `release`.
   - Required reviewers: al menos una persona que no sea quien empuja el tag.
   - Deployment branches and tags: solo tags que coincidan con `v*`.
   - No hace falta ningún secret dentro del environment.

2. **Trusted Publisher en PyPI**, en el proyecto `tempus-ddb`:
   - Owner: `tempus-protocol`.
   - Repository: `tempus-ddb`.
   - Workflow: `release.yml`.
   - Environment: `release`.
   - Si ya existe un publisher de este workflow sin environment, hay que
     actualizarlo. Con el environment vacío en PyPI, el token OIDC de este
     job no coincide y PyPI responde 403.
   - No se usa `PYPI_API_TOKEN` ni ninguna contraseña.

3. **Trusted Publisher en crates.io**, en el crate `tempus-ddb` (Settings →
   Trusted Publishing). El crate ya está publicado, así que no hace falta un
   primer `cargo publish` manual:
   - Owner: `tempus-protocol`.
   - Repository: `tempus-ddb`.
   - Workflow filename: `release.yml`.
   - Environment: `release`.
   - El workflow ya no lee `CARGO_API_TOKEN`. Cuando una publicación OIDC haya
     funcionado, conviene borrar ese secret si todavía existe. Dejarlo no
     activa ningún plan B: el job no lo consulta.

4. **Regla recomendada para los tags.** Un ruleset que solo deje crear tags
   `v*` a quien mantiene el repositorio. El workflow confía en el tag; la
   aprobación del environment es la segunda barrera, no la única.

Nada de esto se aplica al fusionar el cambio. El workflow solo corre cuando
alguien empuja un tag `v*` cuyo commit ya incluye este archivo, o cuando se
lanza a mano.

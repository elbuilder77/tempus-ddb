"""Generate a deterministic SPDX 2.3 dependency inventory without extra packages."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path


def spdx_id(kind, name, version):
    digest = hashlib.sha256(f"{kind}\0{name}\0{version}".encode()).hexdigest()[:16]
    return f"SPDXRef-Package-{digest}"


def cargo_packages(lockfile):
    text = lockfile.read_text(encoding="utf-8")
    packages = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.MULTILINE)
        version = re.search(r'^version = "([^"]+)"', block, re.MULTILINE)
        if name and version:
            packages.append(("cargo", name.group(1), version.group(1)))
    return packages


def python_packages(pyproject):
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r"^dependencies\s*=\s*\[(.*?)^\]", text, re.MULTILINE | re.DOTALL)
    if not match:
        return []
    packages = []
    for requirement in re.findall(r'"([^"]+)"', match.group(1)):
        parsed = re.match(r"([A-Za-z0-9_.-]+)\s*([^;]*)", requirement)
        if parsed:
            constraint = parsed.group(2).strip() or "NOASSERTION"
            packages.append(("pypi", parsed.group(1), constraint))
    return packages


def package(kind, name, version):
    purl_version = f"@{version}" if re.fullmatch(r"[0-9][A-Za-z0-9.+_-]*", version) else ""
    return {
        "name": name,
        "SPDXID": spdx_id(kind, name, version),
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:{kind}/{name}{purl_version}",
            }
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    dependencies = sorted(
        item
        for item in set(
            cargo_packages(root / "Cargo.lock") + python_packages(root / "pyproject.toml")
        )
        if item[1] != "tempus-ddb"
    )
    project_id = "SPDXRef-Package-tempus-ddb"
    source_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    created = (
        dt.datetime.fromtimestamp(int(source_epoch), tz=dt.timezone.utc)
        if source_epoch
        else dt.datetime.now(tz=dt.timezone.utc)
    ).replace(microsecond=0)
    revision = os.environ.get("GITHUB_SHA", "local")
    namespace_hash = hashlib.sha256(f"{args.version}\0{revision}".encode()).hexdigest()
    packages = [
        {
            "name": "tempus-ddb",
            "SPDXID": project_id,
            "versionInfo": args.version,
            "downloadLocation": "https://github.com/tempus-protocol/tempus-ddb",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
        }
    ] + [package(*item) for item in dependencies]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": project_id,
        }
    ] + [
        {
            "spdxElementId": project_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": item["SPDXID"],
        }
        for item in packages[1:]
    ]
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"tempus-ddb-{args.version}",
        "documentNamespace": f"https://github.com/tempus-protocol/tempus-ddb/sbom/{namespace_hash}",
        "creationInfo": {
            "created": created.isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: tempus-ddb/scripts/generate_sbom.py"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

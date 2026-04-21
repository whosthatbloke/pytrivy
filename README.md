# TrivyPy

TrivyPy is a Python SDK that wraps the [Trivy](https://trivy.dev) CLI and turns its JSON output into queryable Python objects. Instead of writing shell scripts to grep through scan results or manually parsing nested JSON, you import a class and call methods.

```python
client = TrivyClient("python:3.13-slim", TrivyScanCommandEnum.Image)
client.scan()

print(client.criticals())           # ['CVE-2024-...', ...]
print(client.vulnerability_in_targets("CVE-2024-1234"))  # ['usr/bin/python3']
print(client.purl("openssl@3.0.2-0ubuntu1.12.x86_64"))  # 'pkg:deb/ubuntu/openssl@...'
```

The same API works whether you just ran a live scan or loaded a JSON file saved weeks ago. Results are stored in the client object — scan once, query as many times as you like.

---

## Installation

```bash
pip install trivypy
```

Or use Docker (Trivy is pre-installed in the image):

```bash
# Clone and cd into repo
docker buildx bake -f docker/docker-bake.hcl
docker run -it docker.io/library/trivy-py:latest python3
```

Trivy must be installed and on your `PATH` to run live scans. To install it:

```bash
brew install trivy          # macOS
# or see https://trivy.dev/latest/getting-started/installation/
```

---

## Core concepts

**Lazy scanning.** Creating a `TrivyClient` does not trigger a scan. You call `.scan()` explicitly, or use `.from_file()` / `.from_dict()` to load existing results. This means you can load a JSON file produced by your CI pipeline and query it locally without re-scanning.

**Consistent API shape.** Every data type (vulnerabilities, licenses, packages) follows the same pattern:

| Method | Returns |
|---|---|
| `raw_X()` | Raw dicts straight from the Trivy JSON |
| `X()` | List of names/IDs |
| `unique_X()` | Deduplicated names/IDs |
| `X_in_targets(name)` | Which targets contain this item |

---

## Classes

### `TrivyClient`

The core class. Wraps a single Trivy scan target.

### `TrivyComparator`

Compares two `TrivyClient` instances to find which CVEs were fixed and which persist across versions.

### `TrivyAnalyzer`

Runs aggregate queries across a collection of `TrivyClient` instances — useful for analysing an entire release or fleet.

---

## Use cases

### 1. Scan a container image

```python
from trivy.classes import TrivyClient
from trivy.enums import TrivyScanCommandEnum
from trivy.reports import generate_excel_report

client = TrivyClient("python:3.13-slim", TrivyScanCommandEnum.Image)
client.scan()

# Counts by severity
print(len(client.criticals()))
print(len(client.highs()))
print(len(client.mediums()))
print(len(client.lows()))
print(len(client.unknowns()))

# All unique CVE IDs
print(client.unique_vulnerabilities())

# Full detail for one CVE
details = client.vulnerability("CVE-2024-1234")
print(details["Severity"], details["Description"])

# Which targets inside the image contain a specific CVE
print(client.vulnerability_in_targets("CVE-2024-1234"))

# Generate an Excel report
generate_excel_report(client)
# -> python__3.13-slim_1718000000_report.xlsx
```

You can also scan a filesystem path or a config directory:

```python
client = TrivyClient("/path/to/app", TrivyScanCommandEnum.FileSystem)
client = TrivyClient("/path/to/infra", TrivyScanCommandEnum.Config)
```

---

### 2. Load saved scan results

If you already have Trivy JSON output (e.g. from CI), load it directly — no re-scan needed.

```python
# From a file on disk
client = TrivyClient.from_file("scan_results.json")

# From a dict already in memory
import json
with open("scan_results.json") as f:
    data = json.load(f)
client = TrivyClient.from_dict(data)
```

`from_dict` and `from_file` automatically detect the scan type (`image`, `fs`, `config`, `sbom`) from the JSON, so you don't need to specify it.

---

### 3. Query licenses

```python
client = TrivyClient("nginx:latest", TrivyScanCommandEnum.Image)
client.scan()

# All license names found in the image
print(client.licenses())              # ['MIT', 'Apache-2.0', 'GPL-2.0', ...]
print(client.unique_licenses())       # deduplicated

# Look up details for a specific license
details = client.license("MIT")

# Which targets inside the image use a specific license
print(client.license_in_targets("GPL-2.0"))
```

---

### 4. Query packages (SBOM)

Every scan result includes the list of packages Trivy found. Package names are **not unique** — the same name can appear in multiple targets with different versions or architectures. Use the Trivy ID or PURL for unambiguous lookups.

```python
client = TrivyClient("python:3.13-slim", TrivyScanCommandEnum.Image)
client.scan()

# All package names (may contain duplicates across targets)
print(client.packages())
print(client.unique_packages())

# Look up all packages with a given name (returns a list — there may be more than one)
matches = client.packages_named("openssl")
for pkg in matches:
    print(pkg["ID"], pkg["Version"])

# Unambiguous lookup by Trivy ID
pkg = client.package_by_id("openssl@3.0.2-0ubuntu1.12.amd64")
print(pkg["Version"])

# PURL — the standard identifier used in CycloneDX/SPDX SBOMs
print(client.purl("openssl@3.0.2-0ubuntu1.12.amd64"))
# -> pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.12?arch=amd64&distro=ubuntu-22.04

# Direct dependencies of a package
print(client.dependencies("openssl@3.0.2-0ubuntu1.12.amd64"))
# -> ['libc6@2.35-0ubuntu3.6.amd64', 'libssl3@3.0.2-0ubuntu1.12.amd64']

# All packages in a specific target
print(client.packages_in_target("python:3.13-slim (debian 12.5)"))
```

You can also scan an existing SBOM file directly:

```python
client = TrivyClient("bom.cdx.json", TrivyScanCommandEnum.SBOM)
client.scan()
```

---

### 5. Generate an SBOM

`sbom()` is a separate Trivy invocation that produces a CycloneDX or SPDX document for the target. It is independent of `scan()` — the target does not need to have been vulnerability-scanned first, and calling `sbom()` does not populate `scan_results()`.

```python
from trivy.classes import TrivyClient
from trivy.enums import TrivyScanCommandEnum, SBOMFormatEnum

client = TrivyClient("python:3.13-slim", TrivyScanCommandEnum.Image)

# Generate a CycloneDX SBOM (default) and get it back as a dict
sbom = client.sbom()
print(sbom["bomFormat"])      # CycloneDX
print(sbom["specVersion"])    # 1.5
print(sbom["components"])     # list of components

# Generate an SPDX SBOM instead
sbom = client.sbom(output_format=SBOMFormatEnum.SPDX)

# Write the output to a file as well as returning the dict
sbom = client.sbom(output_file="python-slim.cdx.json")

# Both options together
sbom = client.sbom(output_format=SBOMFormatEnum.SPDX, output_file="python-slim.spdx.json")
```

Results are cached per format — calling `sbom()` twice with the same format runs Trivy only once:

```python
client.sbom()  # runs Trivy
client.sbom()  # returns cached result

# Access cached results directly
cached = client.sbom_results()
cyclonedx_data = cached[SBOMFormatEnum.CycloneDX]
```

---

### 6. Compare two versions


Use `TrivyComparator` to understand what changed between an old and new version of the same image. Both clients are scanned automatically if they haven't been already.

```python
from trivy.classes import TrivyClient, TrivyComparator
from trivy.enums import TrivyScanCommandEnum

old = TrivyClient("myapp:1.0.0", TrivyScanCommandEnum.Image)
new = TrivyClient("myapp:1.1.0", TrivyScanCommandEnum.Image)

comp = TrivyComparator(old, new)

# CVEs present in 1.0.0 but gone in 1.1.0 — successfully remediated
print(comp.fixed_vulnerabilities())

# CVEs still present in both — carry-over risks that still need attention
print(comp.persisting_vulnerabilities())
```

You can load from saved files to compare without re-scanning:

```python
old = TrivyClient.from_file("myapp_1.0.0_scan.json")
new = TrivyClient.from_file("myapp_1.1.0_scan.json")
comp = TrivyComparator(old, new)
```

---

### 7. Analyse a fleet or release

Use `TrivyAnalyzer` when you have multiple images and want cross-cutting questions: which CVE affects the most images, which image has the most vulnerabilities, what does the severity breakdown look like across everything.

```python
from trivy.classes import TrivyClient, TrivyAnalyzer
from trivy.enums import TrivyScanCommandEnum, SeverityEnum

clients = [
    TrivyClient("myapp-api:1.0.0", TrivyScanCommandEnum.Image),
    TrivyClient("myapp-worker:1.0.0", TrivyScanCommandEnum.Image),
    TrivyClient("myapp-scheduler:1.0.0", TrivyScanCommandEnum.Image),
]

# TrivyAnalyzer scans any unscanned clients automatically
analyzer = TrivyAnalyzer(clients)

# Which image(s) have the most / fewest vulnerabilities
print(analyzer.clients_with_highest_vulnerabilities())
print(analyzer.clients_with_lowest_vulnerabilities())

# Most widespread CVEs — the ones affecting the most images
# Returns [(cve_id, count), ...] sorted by count descending
print(analyzer.most_common_cves(limit=10))

# Bottleneck CVEs — grouped by how many images they appear in,
# with the list of affected clients. Useful for prioritising base image updates.
for cve, count, affected in analyzer.bottlenecks():
    print(f"{cve} affects {count} images: {[c.trivy_target for c in affected]}")

# Severity breakdown across the entire fleet
severities = analyzer.severities()
print(severities[SeverityEnum.Critical.value])  # list of unique critical CVE IDs
print(severities[SeverityEnum.High.value])

# Find which images contain a specific CVE
affected = analyzer.find_images_with_cve("CVE-2024-1234")
print([c.trivy_target for c in affected])
```

**Comparing two releases** — load the old release from saved files and compare the severity profile:

```python
from trivy.enums import SeverityEnum

old_release = TrivyAnalyzer([
    TrivyClient.from_file("v1/api_scan.json"),
    TrivyClient.from_file("v1/worker_scan.json"),
])

new_release = TrivyAnalyzer([
    TrivyClient.from_file("v2/api_scan.json"),
    TrivyClient.from_file("v2/worker_scan.json"),
])

old_sev = old_release.severities()
new_sev = new_release.severities()

for severity in SeverityEnum:
    old_count = len(old_sev[severity.value])
    new_count = len(new_sev[severity.value])
    delta = old_count - new_count
    print(f"{severity.value}: {old_count} -> {new_count}  ({'+' if delta >= 0 else ''}{delta} resolved)")

print(f"Total unique CVEs resolved: "
      f"{len(old_release.unique_vulnerabilities()) - len(new_release.unique_vulnerabilities())}")
```

---

### 8. Generate an Excel report

`generate_excel_report` produces a multi-sheet `.xlsx` file from any scanned `TrivyClient`.

```python
from trivy.classes import TrivyClient
from trivy.enums import TrivyScanCommandEnum
from trivy.reports import generate_excel_report

client = TrivyClient("nginx:latest", TrivyScanCommandEnum.Image)
client.scan()

# Auto-generated filename: nginx__latest_1718000000_report.xlsx
filename = generate_excel_report(client)

# Or specify your own filename (no extension needed)
generate_excel_report(client, filename="nginx_report.xlsx")
```

The workbook contains four sheets:

| Sheet | Contents |
|---|---|
| **Severity Summary** | Count of CVEs per severity level plus a total |
| **Vulnerabilities** | One row per CVE with ID, severity, description, package name, installed version, fixed version, and all CVSS scores flattened to columns |
| **Packages** | One row per package with target, ecosystem type, Trivy ID, name, version, licenses, and PURL |
| **Targets** | List of all scan targets found inside the image |

---

## Exception handling

All lookup methods raise specific exceptions when an item is not found, so you can handle them cleanly.

```python
from trivy.exceptions import (
    VulnerabilityDoesntExist,
    LicenseDoesntExist,
    PackageDoesntExist,
    TargetDoesntExist,
    TrivyClientNotScanned,
    UnknownImage,
)

# Vulnerability lookup
try:
    client.vulnerability("CVE-2099-99999")
except VulnerabilityDoesntExist:
    print("CVE not found in this scan")

# Generating a report before scanning
try:
    generate_excel_report(client)
except TrivyClientNotScanned:
    client.scan()
    generate_excel_report(client)

# Scanning an image that doesn't exist
try:
    client.scan()
except UnknownImage:
    print("Image not found in registry")
```

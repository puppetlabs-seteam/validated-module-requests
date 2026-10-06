#!/usr/bin/env python3
"""
PostgreSQL module investigation tool.

Python version of the PowerShell investigation workflow. It combines:
- Puppet Forge module source scanning
- Forge Validated coverage metadata
- Forge download counts
- PostgreSQL evidence classification
- Optional Hiera/control-repo evidence scanning
- Full, summary, JSON, error, and Hiera evidence reports

Expected repo layout:
  _forge_modules/inventory/forge_inventory.json
  _forge_modules/extracted/...

Outputs:
  _forge_modules/reports/postgresql_reference_report.json
  _forge_modules/reports/postgresql_reference_report.md
  _forge_modules/reports/postgresql_reference_summary.md
  _forge_modules/reports/postgresql_reference_errors.json
  _forge_modules/reports/hiera_postgresql_evidence.json, when Hiera scanning is enabled
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

POSTGRES_TERMS = [
    "postgresql",
    "postgres",
    "pgsql",
    "pg_",
    "pgbouncer",
    "pgpass",
    "postgres_exporter",
    "geo_postgresql",
    "5432",
    "database",
    "db_host",
    "db_port",
    "db_user",
    "db_password",
    "store_git_keys_in_db",
    "ompgsql",
    "pg_hba",
]

FORGE_EXTENSIONS = {
    ".pp",
    ".erb",
    ".epp",
    ".yaml",
    ".yml",
    ".json",
    ".md",
    ".sh",
    ".rb",
    ".conf",
    ".txt",
}

HIERA_EXTENSIONS = {".yaml", ".yml", ".json", ".pp"}

HIERA_PATTERNS = [
    "gitlab::postgresql",
    "gitlab::geo_postgresql",
    "gitlab::pgbouncer",
    "gitlab::postgres_exporter",
    "gitlab::pgbouncer_exporter",
    "gitlab::pgpass_file_ensure",
    "gitlab::pgpass_file_location",
    "gitlab::pgbouncer_password",
    "gitlab::store_git_keys_in_db",
    "nftables::rules::out::postgres",
    "ompgsql",
    "rsyslog::actions::outputs::ompgsql",
    "pg_hba",
    "postgresql",
    "pgbouncer",
    "pgpass",
]

FORGE_API_BASE = "https://forgeapi.puppet.com/v3"


def section(message: str) -> None:
    print()
    print(f"===== {message} =====")


def read_text_safe(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return path.read_text(encoding=encoding, errors="replace")
        except UnicodeDecodeError:
            continue
    return path.read_text(errors="replace")


def markdown_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    text = text.replace("|", "\\|")
    text = text.replace("\r", " ").replace("\n", " ")
    return text


def shorten(text: str, limit: int = 240) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def format_nullable_number(value: Any) -> str:
    if value is None:
        return "unknown"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def forge_get_json(url: str, timeout: int = 30) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "postgres-investigator/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - operator-controlled Forge API URL
        data = response.read().decode("utf-8", errors="replace")
    return json.loads(data)


def load_inventory(inventory_path: Path) -> dict[str, Any]:
    return json.loads(read_text_safe(inventory_path))


def inventory_modules(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    return [m for m in inventory.get("modules", []) if m.get("status") == "ok"]


def collect_forge_coverage_metadata(modules: list[dict[str, Any]], skip_web: bool = False) -> dict[str, dict[str, Any]]:
    """Collect Validated status and downloads without removing inventory-derived metadata.

    The downloader inventory remains the source of truth for module list/version used in the scan.
    Forge lookups are used to enrich the report with Validated status and download counts.
    """
    coverage: dict[str, dict[str, Any]] = {}
    validated_map: dict[str, dict[str, Any]] = {}

    if not skip_web:
        try:
            url = f"{FORGE_API_BASE}/modules?endorsements=validated&limit=100&fields=slug,downloads,current_release"
            response = forge_get_json(url)
            for item in response.get("results", []):
                slug = str(item.get("slug", ""))
                if slug:
                    validated_map[slug] = item
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: Could not retrieve Forge validated metadata: {exc}")

    for module in modules:
        name = str(module.get("module", ""))
        version = str(module.get("version", ""))
        validated = False
        downloads: Any = None
        forge_version = version

        if name in validated_map:
            item = validated_map[name]
            validated = True
            downloads = item.get("downloads")
            current_release = item.get("current_release") or {}
            if current_release.get("version"):
                forge_version = str(current_release.get("version"))
        elif not skip_web:
            try:
                response = forge_get_json(f"{FORGE_API_BASE}/modules/{name}")
                downloads = response.get("downloads")
                current_release = response.get("current_release") or {}
                if downloads is None:
                    downloads = current_release.get("downloads")
                if current_release.get("version"):
                    forge_version = str(current_release.get("version"))
            except Exception:
                # Keep inventory-derived details if Forge metadata lookup fails.
                pass

        dependencies = module.get("dependencies") or []
        tasks = module.get("tasks") or []

        coverage[name] = {
            "module": name,
            "validated": validated,
            "validated_status": "validated" if validated else "not validated",
            "downloads": downloads,
            "forge_version": forge_version,
            "supported": module.get("supported"),
            "source": module.get("source"),
            "dependency_count": len(dependencies) if isinstance(dependencies, list) else 0,
            "task_count": len(tasks) if isinstance(tasks, list) else 0,
        }

    return coverage


def finding_area(path_text: str) -> str:
    normalized = path_text.replace("\\", "/").lower()
    if re.search(r"/spec/|/test/|/tests/|/fixtures/|/acceptance/", normalized):
        return "test"
    if re.search(r"/readme|/changelog|/reference|\.md$|/docs/|/documentation/", normalized):
        return "documentation"
    if re.search(r"/manifests/|/templates/|/tasks/|/plans/|/files/|/lib/", normalized):
        return "source"
    if "/data/" in normalized:
        return "data"
    if normalized.endswith(".pp"):
        return "source"
    if normalized.endswith((".yaml", ".yml", ".json")):
        return "data"
    return "other"


def finding_evidence(line: str, path_text: str) -> str:
    lower = line.lower()
    area = finding_area(path_text)
    postgres_terms = [
        "postgresql",
        "postgres",
        "pgbouncer",
        "pgpass",
        "postgres_exporter",
        "geo_postgresql",
        "store_git_keys_in_db",
        "ompgsql",
        "pg_hba",
    ]
    for term in postgres_terms:
        if term in lower:
            return "source-postgresql" if area in {"source", "data"} else "reference-postgresql"
    if "database" in lower or "db_" in lower:
        return "generic-database"
    if "pg_" in lower or "5432" in lower:
        return "weak-token"
    return "unknown"


def risk_level(source: int, reference: int, generic: int, weak: int) -> str:
    if source >= 5:
        return "high"
    if source > 0:
        return "medium"
    if reference >= 5:
        return "medium"
    if reference + generic > 0:
        return "low"
    if weak > 0:
        return "low"
    return "none"


def evidence_summary(source: int, reference: int, generic: int, weak: int) -> str:
    parts: list[str] = []
    if source:
        parts.append(f"source PostgreSQL={source}")
    if reference:
        parts.append(f"docs/tests PostgreSQL={reference}")
    if generic:
        parts.append(f"generic database={generic}")
    if weak:
        parts.append(f"weak token={weak}")
    return "; ".join(parts) if parts else "none"


def review_category(module: str, findings: list[dict[str, Any]], terms: list[str]) -> str:
    module_lower = module.lower()
    term_set = {term.lower() for term in terms}
    paths = [str(f.get("path", "")).replace("\\", "/").lower() for f in findings]

    if module_lower == "puppet-gitlab":
        return "direct-postgresql-management"
    if module_lower == "puppet-nftables" or any("rules/out/postgres" in path for path in paths):
        return "postgresql-connectivity"
    if module_lower == "puppet-augeasproviders_core" or "pg_hba" in term_set:
        return "postgresql-access-config"
    if module_lower == "puppet-rsyslog" or "ompgsql" in term_set:
        return "postgresql-output-plugin"
    if {"postgres", "postgresql", "pgbouncer"} & term_set:
        return "postgresql-related-capability"
    if {"database", "db_password"} & term_set:
        return "generic-database-only"
    if {"pg_", "5432"} & term_set:
        return "weak-token-only"
    return "no-evidence"


def confidence(category: str, source: int, reference: int, generic: int, weak: int) -> str:
    if category == "direct-postgresql-management" and source > 0:
        return "confirmed-capability"
    if category in {"postgresql-connectivity", "postgresql-output-plugin", "postgresql-access-config"}:
        return "conditional"
    if source > 0:
        return "likely"
    if reference > 0:
        return "contextual"
    if generic + weak > 0:
        return "weak"
    return "none"


def validation_questions(category: str) -> list[str]:
    if category == "direct-postgresql-management":
        return [
            "Are any GitLab PostgreSQL-related Hiera keys set, such as gitlab::postgresql, gitlab::geo_postgresql, gitlab::pgbouncer, gitlab::postgres_exporter, gitlab::pgbouncer_exporter, gitlab::pgpass_file_ensure, or gitlab::store_git_keys_in_db?",
            "Is the module used to render /etc/gitlab/gitlab.rb PostgreSQL, Geo PostgreSQL, PgBouncer, or exporter settings?",
            "Are the postgres_upgrade or post_upgrade tasks used operationally?",
        ]
    if category == "postgresql-connectivity":
        return ["Is the PostgreSQL connectivity class or rule included anywhere, and does PostgreSQL still use TCP port 5432 after the upgrade?"]
    if category == "postgresql-access-config":
        return ["Does the control repo use this module/provider to manage pg_hba.conf or other PostgreSQL access-control files?"]
    if category == "postgresql-output-plugin":
        return ["Is rsyslog configured to use the ompgsql PostgreSQL output module or send logs to a PostgreSQL database?"]
    return []


def sort_key(result: dict[str, Any]) -> tuple[int, str]:
    order = {"high": 1, "medium": 2, "low": 3, "none": 4}
    return (order.get(str(result.get("risk", "unknown")), 5), str(result.get("module", "")))


def finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, int]:
    order = {"source-postgresql": 1, "reference-postgresql": 2, "generic-database": 3, "weak-token": 4}
    return (
        order.get(str(finding.get("evidence", "unknown")), 5),
        str(finding.get("path", "")),
        int(finding.get("line_number", 0) or 0),
    )


def scan_forge_modules(modules: list[dict[str, Any]], repo_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for module in modules:
        module_name = str(module.get("module", ""))
        version = str(module.get("version", ""))
        extract_path = Path(str(module.get("extract_path", "")))
        print(f"Scanning {module_name} {version}")

        if not extract_path.exists():
            results.append(
                {
                    "module": module_name,
                    "version": version,
                    "status": "extract_path_missing",
                    "risk": "unknown",
                    "match_count": 0,
                    "source_postgresql_matches": 0,
                    "reference_postgresql_matches": 0,
                    "generic_database_matches": 0,
                    "weak_token_matches": 0,
                    "evidence_summary": "extract path missing",
                    "review_category": "unknown",
                    "confidence": "none",
                    "matched_terms": [],
                    "findings": [],
                    "customer_validation_questions": [],
                }
            )
            continue

        findings: list[dict[str, Any]] = []
        matched_terms: set[str] = set()

        try:
            files = [p for p in extract_path.rglob("*") if p.is_file() and p.suffix.lower() in FORGE_EXTENSIONS]
        except Exception as exc:  # noqa: BLE001
            errors.append({"module": module_name, "version": version, "operation": "enumerate_files", "path": str(extract_path), "message": str(exc)})
            files = []

        for path in files:
            try:
                text = read_text_safe(path)
            except Exception as exc:  # noqa: BLE001
                errors.append({"module": module_name, "version": version, "operation": "read_file", "path": str(path), "message": str(exc)})
                continue

            rel = relative_path(path, repo_root)
            for line_number, line in enumerate(text.splitlines(), start=1):
                lower = line.lower()
                line_terms = [term for term in POSTGRES_TERMS if term.lower() in lower]
                if not line_terms:
                    continue
                matched_terms.update(term.lower() for term in line_terms)
                findings.append(
                    {
                        "path": rel,
                        "area": finding_area(rel),
                        "evidence": finding_evidence(line, rel),
                        "line_number": line_number,
                        "line": line.strip(),
                    }
                )

        terms_sorted = sorted(matched_terms)
        source = sum(1 for f in findings if f["evidence"] == "source-postgresql")
        reference = sum(1 for f in findings if f["evidence"] == "reference-postgresql")
        generic = sum(1 for f in findings if f["evidence"] == "generic-database")
        weak = sum(1 for f in findings if f["evidence"] == "weak-token")
        category = review_category(module_name, findings, terms_sorted)

        results.append(
            {
                "module": module_name,
                "version": version,
                "status": "ok",
                "risk": risk_level(source, reference, generic, weak),
                "match_count": len(findings),
                "source_postgresql_matches": source,
                "reference_postgresql_matches": reference,
                "generic_database_matches": generic,
                "weak_token_matches": weak,
                "evidence_summary": evidence_summary(source, reference, generic, weak),
                "review_category": category,
                "confidence": confidence(category, source, reference, generic, weak),
                "matched_terms": terms_sorted,
                "findings": findings,
                "customer_validation_questions": validation_questions(category),
            }
        )

    return results, errors


def hiera_module_hint(line: str) -> str:
    lower = line.lower()
    if "gitlab::" in lower or "include gitlab" in lower or "class { 'gitlab" in lower or 'class { "gitlab' in lower:
        return "puppet-gitlab"
    if "nftables::rules::out::postgres" in lower:
        return "puppet-nftables"
    if "rsyslog" in lower or "ompgsql" in lower:
        return "puppet-rsyslog"
    if "pg_hba" in lower or "augeasproviders" in lower:
        return "puppet-augeasproviders_core"
    return "unknown"


def hiera_finding_type(line: str) -> str:
    trimmed = line.strip()
    if re.search(r"^[\"']?[A-Za-z0-9_:.-]+[\"']?\s*:", trimmed):
        return "hiera-key"
    if re.search(r"lookup\s*\(", trimmed):
        return "puppet-lookup"
    if re.search(r"class\s*\{|include\s+", trimmed):
        return "puppet-class-reference"
    return "text-reference"


def scan_hiera(hiera_path: Path | None, repo_root: Path) -> dict[str, Any]:
    if hiera_path is None:
        return {"status": "not_requested", "path": None, "findings": [], "errors": [], "patterns": HIERA_PATTERNS}
    if not hiera_path.exists():
        return {"status": "path_missing", "path": str(hiera_path), "findings": [], "errors": [], "patterns": HIERA_PATTERNS}
    if not hiera_path.is_dir():
        return {"status": "not_directory", "path": str(hiera_path), "findings": [], "errors": [], "patterns": HIERA_PATTERNS}

    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    files = [p for p in hiera_path.rglob("*") if p.is_file() and p.suffix.lower() in HIERA_EXTENSIONS]

    for path in files:
        try:
            text = read_text_safe(path)
        except Exception as exc:  # noqa: BLE001
            errors.append({"module": "hiera", "version": "n/a", "operation": "read_file", "path": str(path), "message": str(exc)})
            continue
        rel = relative_path(path, repo_root)
        for line_number, line in enumerate(text.splitlines(), start=1):
            lower = line.lower()
            matched = sorted({pattern for pattern in HIERA_PATTERNS if pattern.lower() in lower})
            if not matched:
                continue
            findings.append(
                {
                    "path": rel,
                    "line_number": line_number,
                    "finding_type": hiera_finding_type(line),
                    "module_hint": hiera_module_hint(line),
                    "matched_patterns": matched,
                    "line": line.strip(),
                }
            )

    return {"status": "ok", "path": str(hiera_path), "findings": findings, "errors": errors, "patterns": HIERA_PATTERNS}


def hiera_for_module(module: str, hiera_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in hiera_findings:
        line = str(finding.get("line", "")).lower()
        if finding.get("module_hint") == module:
            result.append(finding)
        elif module == "puppet-gitlab" and "gitlab" in line:
            result.append(finding)
    return result


def write_reports(
    results: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    hiera_scan: dict[str, Any] | None,
    coverage: dict[str, dict[str, Any]],
    reports_dir: Path,
    inventory_path: Path,
    scanned_modules: int,
) -> dict[str, Path | None]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_report = reports_dir / "postgresql_reference_report.json"
    markdown_report = reports_dir / "postgresql_reference_report.md"
    summary_report = reports_dir / "postgresql_reference_summary.md"
    error_report = reports_dir / "postgresql_reference_errors.json"
    hiera_report = reports_dir / "hiera_postgresql_evidence.json"

    hiera_status = "not_analyzed"
    hiera_findings: list[dict[str, Any]] = []
    hiera_errors: list[dict[str, Any]] = []
    if hiera_scan is not None:
        hiera_status = str(hiera_scan.get("status", "unknown"))
        hiera_findings = list(hiera_scan.get("findings", []))
        hiera_errors = list(hiera_scan.get("errors", []))

    all_errors = errors + hiera_errors
    sorted_results = sorted(results, key=sort_key)
    validated_count = sum(1 for item in coverage.values() if item.get("validated"))
    not_validated_count = sum(1 for item in coverage.values() if not item.get("validated"))

    report_payload = {
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "inventoryPath": str(inventory_path),
        "scannedModules": scanned_modules,
        "forgeCoverage": {"validated": validated_count, "not_validated": not_validated_count, "modules": list(coverage.values())},
        "terms": POSTGRES_TERMS,
        "results": results,
        "hiera": hiera_scan,
        "errors": all_errors,
    }
    json_report.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    error_report.write_text(json.dumps(all_errors, indent=2), encoding="utf-8")
    if hiera_scan is not None:
        hiera_report.write_text(json.dumps(hiera_scan, indent=2), encoding="utf-8")

    today = date.today().isoformat()
    md: list[str] = []
    md += ["# PostgreSQL Reference Scan", "", f"_Last updated: {today}_", ""]
    md += [
        "This report combines Forge validation coverage, PostgreSQL source/reference evidence, and optional Hiera/control-repo evidence.",
        "",
        "## Forge Coverage",
        "",
        f"- Forge modules scanned: {scanned_modules}",
        f"- Validated modules: {validated_count}",
        f"- Not validated modules: {not_validated_count}",
        "",
        "## Hiera / Control Repo Evidence",
        "",
        f"Hiera scan status: **{hiera_status}**",
        "",
        f"Hiera/control-repo findings: {len(hiera_findings)}",
        "",
        "## How Evidence Is Classified",
        "",
        "- **source-postgresql**: PostgreSQL-specific term in module source, data, templates, tasks, files, or library code.",
        "- **reference-postgresql**: PostgreSQL-specific term in docs, changelogs, references, tests, fixtures, or examples.",
        "- **generic-database**: Generic database term without PostgreSQL-specific evidence.",
        "- **weak-token**: Weak indicators such as `pg_` or `5432`.",
        "",
        "## Summary",
        "",
        "| Module | Version | Validated | Downloads | Risk | Confidence | Review Category | Matches | Evidence Summary | Hiera Evidence |",
        "|--------|---------|-----------|-----------|------|------------|-----------------|---------|------------------|----------------|",
    ]
    for item in sorted_results:
        cov = coverage.get(str(item.get("module", "")), {})
        module_hiera = hiera_for_module(str(item.get("module", "")), hiera_findings)
        if hiera_status == "ok":
            hiera_evidence = f"found={len(module_hiera)}" if module_hiera else "not found"
        else:
            hiera_evidence = hiera_status
        md.append(
            f"| {markdown_cell(item.get('module'))} | {markdown_cell(item.get('version'))} | {markdown_cell(cov.get('validated_status', 'unknown'))} | {markdown_cell(format_nullable_number(cov.get('downloads')))} | {markdown_cell(item.get('risk'))} | {markdown_cell(item.get('confidence'))} | {markdown_cell(item.get('review_category'))} | {item.get('match_count')} | {markdown_cell(item.get('evidence_summary'))} | {markdown_cell(hiera_evidence)} |"
        )

    md += ["", "## Follow-up Questions", ""]
    for item in sorted_results:
        for question in item.get("customer_validation_questions", []):
            pass
        if item.get("customer_validation_questions"):
            md += [f"### {item.get('module')}", ""]
            for question in item.get("customer_validation_questions", []):
                md.append(f"- {question}")
            md.append("")

    md += ["## Findings by Module", ""]
    for item in [r for r in sorted_results if int(r.get("match_count", 0)) > 0]:
        md += [
            f"### {item.get('module')} {item.get('version')}",
            "",
            f"Risk: **{item.get('risk')}**",
            "",
            f"Confidence: **{item.get('confidence')}**",
            "",
            f"Review category: **{item.get('review_category')}**",
            "",
            f"Evidence summary: {item.get('evidence_summary')}",
            "",
            "| Area | Evidence | File | Line | Text |",
            "|------|----------|------|------|------|",
        ]
        for finding in sorted(item.get("findings", []), key=finding_sort_key):
            md.append(
                f"| {markdown_cell(finding.get('area'))} | {markdown_cell(finding.get('evidence'))} | {markdown_cell(finding.get('path'))} | {finding.get('line_number')} | `{markdown_cell(shorten(str(finding.get('line', ''))))}` |"
            )
        md.append("")

    if all_errors:
        md += ["## Scan Errors", "", f"Some files or modules could not be scanned. See `{error_report}` for full details."]

    markdown_report.write_text("\n".join(md) + "\n", encoding="utf-8")

    review_items = [
        r
        for r in sorted_results
        if r.get("risk") != "none" and r.get("review_category") not in {"weak-token-only", "generic-database-only"}
    ]
    primary_items = [r for r in sorted_results if r.get("risk") == "high" or r.get("review_category") == "direct-postgresql-management"]
    conditional_items = [
        r
        for r in sorted_results
        if r.get("review_category") in {"postgresql-connectivity", "postgresql-access-config", "postgresql-output-plugin", "postgresql-related-capability"}
    ]
    weak_items = [r for r in sorted_results if r.get("review_category") in {"generic-database-only", "weak-token-only"}]
    no_evidence_items = [r for r in sorted_results if r.get("review_category") == "no-evidence"]

    summary: list[str] = []
    summary += ["# PostgreSQL Investigation Summary", "", f"_Last updated: {today}_", ""]
    summary += [
        "## Result",
        "",
        f"- Forge modules scanned: {scanned_modules}",
        f"- Forge validated coverage: {validated_count}/{scanned_modules}",
        f"- Hiera/control-repo scan: {hiera_status}",
        f"- Hiera/control-repo findings: {len(hiera_findings)}",
        f"- Scan errors: {len(all_errors)}",
        "",
        "## Modules Requiring Review",
        "",
        "| Module | Version | Validated | Downloads | Risk | Confidence | Category | Evidence | Hiera Evidence |",
        "|--------|---------|-----------|-----------|------|------------|----------|----------|----------------|",
    ]
    if not review_items:
        summary.append("| None | | | | none | none | no-evidence | No PostgreSQL-relevant module findings require review. | |")
    else:
        for item in review_items:
            cov = coverage.get(str(item.get("module", "")), {})
            module_hiera = hiera_for_module(str(item.get("module", "")), hiera_findings)
            if hiera_status == "ok":
                hiera_evidence = f"found={len(module_hiera)}" if module_hiera else "not found"
            else:
                hiera_evidence = hiera_status
            summary.append(
                f"| {markdown_cell(item.get('module'))} | {markdown_cell(item.get('version'))} | {markdown_cell(cov.get('validated_status', 'unknown'))} | {markdown_cell(format_nullable_number(cov.get('downloads')))} | {markdown_cell(item.get('risk'))} | {markdown_cell(item.get('confidence'))} | {markdown_cell(item.get('review_category'))} | {markdown_cell(item.get('evidence_summary'))} | {markdown_cell(hiera_evidence)} |"
            )
    summary += ["", "## Current Interpretation", ""]
    if primary_items:
        summary.append(f"- Primary review target(s): {', '.join(sorted({str(i.get('module')) for i in primary_items}))}.")
    else:
        summary.append("- No primary PostgreSQL management target was identified.")
    if conditional_items:
        summary.append(
            f"- Conditional review target(s): {', '.join(sorted({str(i.get('module')) for i in conditional_items}))}. These need configuration evidence before treating them as customer impact."
        )
    if weak_items:
        summary.append(f"- Weak or generic evidence was found in {len(weak_items)} module(s). These should not drive conclusions without stronger evidence.")
    summary.append(f"- Modules with no PostgreSQL evidence: {len(no_evidence_items)}.")
    if hiera_status == "ok" and not hiera_findings:
        summary.append("- No Hiera/control-repo evidence was found in the scanned path.")
    elif hiera_status == "path_missing":
        summary.append("- Hiera/control-repo path was missing, so no usage validation was performed.")
    elif hiera_findings:
        summary.append("- Hiera/control-repo evidence was found. Review the Hiera evidence section in the full report.")

    summary += ["", "## Report Files", "", f"- Full report: `{markdown_report}`", f"- JSON report: `{json_report}`", f"- Error report: `{error_report}`"]
    if hiera_scan is not None:
        summary.append(f"- Hiera evidence: `{hiera_report}`")
    summary_report.write_text("\n".join(summary) + "\n", encoding="utf-8")

    return {
        "json_report": json_report,
        "markdown_report": markdown_report,
        "summary_report": summary_report,
        "error_report": error_report,
        "hiera_report": hiera_report if hiera_scan is not None else None,
    }


def print_summary(reports_dir: Path) -> None:
    summary_path = reports_dir / "postgresql_reference_summary.md"
    if not summary_path.exists():
        raise FileNotFoundError(f"Summary report not found: {summary_path}. Run a scan first.")
    print(read_text_safe(summary_path))


def show_menu() -> str:
    print()
    print("PostgreSQL Module Investigation")
    print("1. Run Forge module scan only")
    print("2. Run Forge module scan + Hiera/control-repo scan using default ./hiera")
    print("3. Run Forge module scan + Hiera/control-repo scan using custom path")
    print("4. Exit")
    print("5. Print latest summary report")
    print()
    return input("Select an option: ").strip()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan downloaded Puppet Forge modules and optional Hiera/control-repo data for PostgreSQL evidence.")
    parser.add_argument("--inventory-path", default="./_forge_modules/inventory/forge_inventory.json")
    parser.add_argument("--reports-dir", default="./_forge_modules/reports")
    parser.add_argument("--hiera-path", default="./hiera")
    parser.add_argument("--skip-hiera", action="store_true")
    parser.add_argument("--skip-forge-coverage", action="store_true", help="Do not call the Forge API for Validated/download metadata.")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--summary-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = Path.cwd()
    inventory_path = Path(args.inventory_path)
    reports_dir = Path(args.reports_dir)
    hiera_path: Path | None = Path(args.hiera_path)
    skip_hiera = args.skip_hiera

    try:
        if args.summary_only:
            print_summary(reports_dir)
            return 0

        if not args.non_interactive:
            choice = show_menu()
            if choice == "1":
                skip_hiera = True
            elif choice == "2":
                skip_hiera = False
                hiera_path = Path("./hiera")
            elif choice == "3":
                skip_hiera = False
                custom = input("Enter Hiera/control-repo path: ").strip()
                hiera_path = Path(custom)
            elif choice == "4":
                print("Exiting.")
                return 0
            elif choice == "5":
                print_summary(reports_dir)
                return 0
            else:
                raise ValueError(f"Invalid menu option: {choice}")

        section("Preparing scan")
        if not inventory_path.exists():
            raise FileNotFoundError(f"Inventory file not found: {inventory_path}. Run download_forge_modules.ps1 first.")
        inventory = load_inventory(inventory_path)
        modules = inventory_modules(inventory)
        print(f"Inventory: {inventory_path}")
        print(f"Modules to scan: {len(modules)}")
        print(f"Reports dir: {reports_dir}")

        section("Collecting Forge validation coverage")
        coverage = collect_forge_coverage_metadata(modules, skip_web=args.skip_forge_coverage)
        validated_count = sum(1 for item in coverage.values() if item.get("validated"))
        print(f"Validated modules: {validated_count}/{len(modules)}")

        section("Scanning Forge modules")
        results, errors = scan_forge_modules(modules, repo_root)

        hiera_scan = None
        if skip_hiera:
            section("Skipping Hiera/control-repo scan")
        else:
            section("Scanning Hiera/control-repo evidence")
            print(f"Hiera/control-repo path: {hiera_path}")
            hiera_scan = scan_hiera(hiera_path, repo_root)
            print(f"Hiera scan status: {hiera_scan.get('status')}")
            print(f"Hiera findings:    {len(hiera_scan.get('findings', []))}")

        section("Writing reports")
        paths = write_reports(results, errors, hiera_scan, coverage, reports_dir, inventory_path, len(modules))

        section("Complete")
        print(f"JSON report:      {paths['json_report']}")
        print(f"Markdown report:  {paths['markdown_report']}")
        print(f"Summary report:   {paths['summary_report']}")
        print(f"Error report:     {paths['error_report']}")
        if paths.get("hiera_report") is not None:
            print(f"Hiera report:     {paths['hiera_report']}")
        print(f"Scan errors:      {len(errors) + (len(hiera_scan.get('errors', [])) if hiera_scan else 0)}")
        print()
        print("Module Summary")
        print("--------------")
        for item in sorted(results, key=sort_key):
            cov = coverage.get(str(item.get("module", "")), {})
            print(
                f"{item['module']:<32} {item['version']:<8} {cov.get('validated_status', 'unknown'):<14} {format_nullable_number(cov.get('downloads')):<12} {item['risk']:<7} {item['confidence']:<22} {item['review_category']:<32} {item['evidence_summary']}"
            )
        return 0
    except Exception as exc:  # noqa: BLE001
        print()
        print("===== FATAL ERROR =====")
        print(f"Message: {exc}")
        print(f"Type:    {type(exc).__name__}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

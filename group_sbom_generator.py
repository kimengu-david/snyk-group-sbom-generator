#!/usr/bin/env python3
"""
Group-level SBOM generator for Snyk.

Not an officially supported Snyk tool - example/reference code, modeled on
an existing org-level SBOM-generation pattern, extended with an outer loop
over every org in a Group.

Flow: List all Orgs in a Group -> List all Projects in each Org -> generate
an SBOM for each eligible Project. Writes ONE SBOM FILE PER PROJECT under
<outputDir>/<org_slug>/<project>.<format_ext> - this does not merge
projects into a single combined document.

Scale notes: both the per-org project listing and the SBOM fetches run
through the same bounded thread pool (--concurrency), so wall-clock time
now tracks total project count more than org count. Rough math at ~0.4s/call
(measured) and concurrency 10: ~100 orgs/1,000 projects in well under a
minute; ~1,000 orgs/10,000 projects in a few minutes; low tens of thousands
of orgs/projects starts climbing into the 10-20 minute range. That's
wall-clock time under ideal conditions - it doesn't account for how a given
tenant's actual API rate limits hold up at that request volume, which this
hasn't been stress-tested against:
  - Concurrent SBOM fetches (--concurrency), default 8 workers.
  - Rate-limit aware: retries on 429/5xx with backoff, honoring Retry-After.
  - Resumable by default: if a project's SBOM file already exists on disk,
    it's read from disk instead of re-fetched (pass --force to disregard).
  - Per-project dependency trees are written as their OWN small HTML files
    under <outputDir>/trees/<org>/<project>.html, and the main report just
    links to them - keeps the main report.html small regardless of how many
    projects there are (embedding thousands of trees in one page doesn't).

Uses only the Python standard library (no pysnyk / requests dependency).
Requires the SNYK_API_TOKEN environment variable.
"""
import argparse
import collections
import concurrent.futures
import csv
import dataclasses
import datetime
import html
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

API_ROOT = "https://api.snyk.io"
API_VERSION = "2024-08-22"
MAX_RETRIES = 5
BACKOFF_BASE = 1.0
BACKOFF_CAP = 30.0

# Project types the SBOM endpoint doesn't support (IaC/config/SAST/Secrets, not Open Source or Container).
# Confirmed live: "secrets" 404s on the SBOM endpoint; the rest are from Snyk's
# documented SBOM scope (Open Source + Container only).
EXCLUDED_PROJECT_TYPES = {
    "helmconfig", "armconfig", "cloudconfig", "terraformplan", "terraformconfig",
    "sast", "cloudformationconfig", "k8sconfig", "secrets",
}

SUPPORTED_FORMATS = [
    "cyclonedx1.4+json", "cyclonedx1.4+xml",
    "cyclonedx1.5+json", "cyclonedx1.5+xml",
    "cyclonedx1.6+json", "cyclonedx1.6+xml",
    "spdx2.3+json",
]


def api_get(path, token, max_retries=MAX_RETRIES):
    """GET a /rest/... path (relative, as returned by links.next), return parsed JSON.
    Retries on 429/5xx with backoff - honors Retry-After when the server sends one."""
    url = f"{API_ROOT}{path}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {token}",
        "Content-Type": "application/vnd.api+json",
    })
    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            retryable = e.code == 429 or e.code >= 500
            attempt += 1
            if not retryable or attempt > max_retries:
                raise
            retry_after = e.headers.get("Retry-After") if e.headers else None
            if retry_after:
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = BACKOFF_CAP
            else:
                wait = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** (attempt - 1))) + random.uniform(0, 0.5)
            time.sleep(wait)


def paginate(path, token):
    """Yield every item across all pages of a JSON:API list endpoint."""
    next_path = path
    while next_path:
        data = api_get(next_path, token)
        for item in data.get("data", []):
            yield item
        next_path = data.get("links", {}).get("next")


def list_orgs_in_group(group_id, token):
    path = f"/rest/groups/{group_id}/orgs?version={API_VERSION}&limit=100"
    return list(paginate(path, token))


def list_projects_in_org(org_id, token):
    path = f"/rest/orgs/{org_id}/projects?version={API_VERSION}&limit=100"
    return list(paginate(path, token))


def generate_sbom(org_id, project_id, sbom_format, token):
    encoded_format = urllib.parse.quote(sbom_format, safe="")
    path = f"/rest/orgs/{org_id}/projects/{project_id}/sbom?version={API_VERSION}&format={encoded_format}"
    return api_get(path, token)


def safe_name(name):
    return name.replace("/", "_").replace(":", "_").replace("|", "_").replace(" ", "_")


def format_ext(sbom_format):
    # e.g. "cyclonedx1.4+json" -> "cyclonedx1.4.json"
    base, ext = sbom_format.split("+")
    return f"{base}.{ext}"


def purl_type(purl):
    """pkg:npm/lodash@4.17.15 -> 'npm'. Returns 'unknown' if absent/unparseable."""
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    rest = purl[len("pkg:"):]
    return rest.split("/", 1)[0] if "/" in rest else rest


def sbom_file_path(output_dir, org_label, project_name, project_id, sbom_format):
    short_id = project_id.split("-")[0]
    return os.path.join(output_dir, org_label, f"{safe_name(project_name)}__{short_id}.{format_ext(sbom_format)}")


# ---------------------------------------------------------------------------
# Report model: aggregated as results come back. Holds only lightweight,
# bounded-size data - per-project dependency graphs are written to their own
# files immediately and NOT retained here, so memory stays proportional to
# "number of projects", not "total size of every dependency tree combined".
# ---------------------------------------------------------------------------

class ReportData:
    def __init__(self, group_id, sbom_format):
        self.group_id = group_id
        self.sbom_format = sbom_format
        self.generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.org_stats = {}  # org_label -> dict(projects=0, components=0, errors=0)
        self.ecosystem_counts = collections.Counter()
        self.component_frequency = collections.Counter()  # "name@version" -> project count
        self.missing_version = []  # (org_label, project_name, component_name)
        self.errors = []  # (org_label, project_name, project_id, code, reason)
        self.unique_components = set()  # (name, version, purl)
        self.total_projects = 0
        self.total_components = 0
        self.project_tree_index = []  # (org_label, project_name, tree_relpath, node_count) - lightweight, for linking
        self.flat_rows = []  # (org_label, project_name, name, version, purl, ecosystem) - one per unique component per project

    def org(self, org_label):
        return self.org_stats.setdefault(org_label, {"projects": 0, "components": 0, "errors": 0})

    def record_sbom(self, org_label, project_name, sbom):
        self.total_projects += 1
        self.org(org_label)["projects"] += 1
        seen_in_project = set()
        for c in sbom.get("components", []):
            name = c.get("name", "?")
            version = c.get("version", "")
            purl = c.get("purl", "")
            key = (name, version, purl)
            if key in seen_in_project:
                continue
            seen_in_project.add(key)

            eco = purl_type(purl)
            self.total_components += 1
            self.org(org_label)["components"] += 1
            self.unique_components.add(key)
            self.ecosystem_counts[eco] += 1
            self.component_frequency[f"{name}@{version}" if version else name] += 1
            self.flat_rows.append((org_label, project_name, name, version, purl, eco))

            if not version:
                self.missing_version.append((org_label, project_name, name))

    def record_error(self, org_label, project_name, project_id, code, reason):
        self.org(org_label)["errors"] += 1
        self.errors.append((org_label, project_name, project_id, code, reason))

    def record_tree(self, org_label, project_name, tree_relpath, node_count):
        self.project_tree_index.append((org_label, project_name, tree_relpath, node_count))


# ---------------------------------------------------------------------------
# Dependency tree: reconstructed from a single SBOM's components + dependencies
# graph (CycloneDX bom-ref / dependsOn linkage). Rendered to its OWN standalone
# HTML file per project - never embedded into the main report - so report size
# stays bounded by project count, not by total dependency-graph size.
# ---------------------------------------------------------------------------

MAX_TREE_DEPTH = 12
MAX_TREE_NODES = 400  # hard cap per project, independent of graph shape

_PAGE_CSS = """
  .viz-root {
    color-scheme: light;
    --surface-1: #fcfcfb;
    --page: #f9f9f7;
    --text-primary: #0b0b0b;
    --text-secondary: #52514e;
    --text-muted: #898781;
    --gridline: #e1e0d9;
    --border: rgba(11,11,11,0.10);
    --good: #0ca30c;
    --warning: #fab219;
    --critical: #d03b3b;
  }
  @media (prefers-color-scheme: dark) {
    :root:where(:not([data-theme="light"])) .viz-root {
      color-scheme: dark;
      --surface-1: #1a1a19;
      --page: #0d0d0d;
      --text-primary: #ffffff;
      --text-secondary: #c3c2b7;
      --text-muted: #898781;
      --gridline: #2c2c2a;
      --border: rgba(255,255,255,0.10);
      --good: #0ca30c;
      --warning: #fab219;
      --critical: #e66767;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: var(--page); color: var(--text-primary); }
  .viz-root { max-width: 980px; margin: 0 auto; padding: 32px 24px 64px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .subtitle { color: var(--text-secondary); font-size: 13px; margin-bottom: 28px; }
  h2 { font-size: 16px; margin: 36px 0 8px; display: flex; align-items: center; gap: 8px; }
  .muted { color: var(--text-muted); font-size: 13px; }
  .stat-tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 8px; }
  .tile { background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
  .tile .value { font-size: 26px; font-weight: 600; font-variant-numeric: tabular-nums; }
  .tile .label { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }
  .bar-row { display: grid; grid-template-columns: 220px 1fr 48px; align-items: center; gap: 10px; padding: 3px 0; }
  .bar-label { font-size: 12.5px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bar-track { background: var(--gridline); border-radius: 3px; height: 10px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 3px; }
  .bar-value { font-size: 12.5px; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-secondary); }
  .legend { margin: 8px 0 16px; display: flex; flex-wrap: wrap; gap: 12px; }
  .legend-chip { font-size: 12px; color: var(--text-secondary); display: inline-flex; align-items: center; gap: 5px; }
  .swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
  th { text-align: left; font-weight: 600; color: var(--text-secondary); border-bottom: 1px solid var(--gridline); padding: 6px 8px; }
  td { padding: 6px 8px; border-bottom: 1px solid var(--gridline); }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .status-icon.good { color: var(--good); }
  .status-icon.warning { color: var(--warning); }
  .status-icon.critical { color: var(--critical); }
  .status-critical { color: var(--critical); font-weight: 600; }

  details.org-node { border: 1px solid var(--border); border-radius: 8px; margin-top: 8px; background: var(--surface-1); }
  details.org-node > summary { padding: 10px 14px; font-weight: 600; cursor: pointer; }
  details.org-node[open] > summary { border-bottom: 1px solid var(--gridline); }
  .project-link-row { margin: 0; padding: 8px 14px 8px 24px; border-bottom: 1px solid var(--gridline); font-size: 13px; }
  .project-link-row:last-child { border-bottom: none; }
  .project-link-row a { color: var(--text-primary); text-decoration: none; }
  .project-link-row a:hover { text-decoration: underline; }
  ul.tree { list-style: none; margin: 6px 0 0; padding-left: 18px; border-left: 1px solid var(--gridline); }
  ul.tree li { margin: 3px 0; font-size: 12.5px; color: var(--text-secondary); }
  li.tree-leaf { padding-left: 2px; }
  details.tree-node { margin: 0; }
  details.tree-node > summary { cursor: pointer; color: var(--text-secondary); }
  details.tree-node > summary:hover { color: var(--text-primary); }
  summary { outline: none; }
  summary::marker { color: var(--text-muted); }
  .back-link { font-size: 13px; }
"""


def _esc(s):
    return html.escape(str(s), quote=True)


def _render_tree_node(ref, comp_map, children_map, ancestors, depth, rendered, budget):
    comp = comp_map.get(ref, {"name": ref, "version": ""})
    label = f"{comp['name']}@{comp['version']}" if comp.get("version") else comp["name"]
    children = children_map.get(ref, [])

    if ref in ancestors:
        return f'<li class="tree-leaf">{_esc(label)} <span class="muted">(cycle, stopped)</span></li>'
    if not children:
        return f'<li class="tree-leaf">{_esc(label)}</li>'
    if depth >= MAX_TREE_DEPTH:
        return f'<li class="tree-leaf">{_esc(label)} <span class="muted">({len(children)}, max depth)</span></li>'
    if budget[0] <= 0:
        return f'<li class="tree-leaf">{_esc(label)} <span class="muted">({len(children)}, truncated)</span></li>'
    if ref in rendered:
        # A dependency graph is a DAG, not a tree: the same package can be depended
        # on from many places. Re-expanding its full subtree every time it's
        # referenced duplicates exponentially - render it once, reference it after.
        return f'<li class="tree-leaf">{_esc(label)} <span class="muted">({len(children)}, expanded above)</span></li>'

    rendered.add(ref)
    budget[0] -= 1
    child_html_parts = []
    for child_ref in children:
        if budget[0] <= 0:
            remaining = len(children) - len(child_html_parts)
            child_html_parts.append(f'<li class="tree-leaf muted">&hellip; {remaining} more not shown (truncated)</li>')
            break
        child_html_parts.append(
            _render_tree_node(child_ref, comp_map, children_map, ancestors | {ref}, depth + 1, rendered, budget)
        )
    child_html = "".join(child_html_parts)

    return f"""<li>
      <details class="tree-node">
        <summary>{_esc(label)} <span class="muted">({len(children)})</span></summary>
        <ul class="tree">{child_html}</ul>
      </details>
    </li>"""


def write_project_tree_file(sbom, org_label, project_name, project_id, output_dir):
    """Builds this project's dependency graph from its own SBOM and writes a small,
    standalone HTML page for it. Returns (relpath_from_output_dir, node_count), or
    None if the SBOM has no usable component graph (e.g. empty project)."""
    comp_map = {}
    for c in sbom.get("components", []):
        bom_ref = c.get("bom-ref")
        if bom_ref:
            comp_map[bom_ref] = {"name": c.get("name", "?"), "version": c.get("version", "")}

    children_map = {
        dep["ref"]: dep.get("dependsOn", [])
        for dep in sbom.get("dependencies", [])
        if dep.get("dependsOn")
    }
    root = sbom.get("metadata", {}).get("component", {})
    root_ref = root.get("bom-ref")
    if not root_ref:
        return None
    comp_map.setdefault(root_ref, {"name": root.get("name", project_name), "version": root.get("version", "")})

    budget = [MAX_TREE_NODES]
    tree_html = _render_tree_node(root_ref, comp_map, children_map, frozenset(), 0, set(), budget)
    node_count = len(comp_map)

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{_esc(project_name)} &mdash; dependency tree</title>
<style>{_PAGE_CSS}</style>
</head>
<body>
<div class="viz-root">
  <p class="back-link"><a href="../../report.html">&larr; back to report</a></p>
  <h1>{_esc(project_name)}</h1>
  <div class="subtitle">{_esc(org_label)} &middot; {node_count} components</div>
  <ul class="tree">{tree_html}</ul>
</div>
</body>
</html>"""

    short_id = project_id.split("-")[0]
    rel_dir = os.path.join("trees", org_label)
    abs_dir = os.path.join(output_dir, rel_dir)
    os.makedirs(abs_dir, exist_ok=True)
    rel_path = os.path.join(rel_dir, f"{safe_name(project_name)}__{short_id}.html")
    with open(os.path.join(output_dir, rel_path), "w") as f:
        f.write(doc)
    return rel_path, node_count


def _bar_rows(pairs, max_value, color_fn):
    """pairs: list of (label, value). Renders one CSS bar per row."""
    rows = []
    for label, value in pairs:
        pct = round((value / max_value) * 100, 1) if max_value else 0
        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label" title="{_esc(label)}">{_esc(label)}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%; background:{color_fn(label)};"></div>
          </div>
          <div class="bar-value">{value}</div>
        </div>""")
    return "\n".join(rows)


_ECOSYSTEM_HUES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]


def build_json_report(report, output_path):
    """Aggregate analytics plus the full flat component list, as structured JSON."""
    r = report
    data = {
        "group_id": r.group_id,
        "sbom_format": r.sbom_format,
        "generated_at": r.generated_at,
        "summary": {
            "orgs_scanned": len(r.org_stats),
            "projects": r.total_projects,
            "total_components": r.total_components,
            "unique_components": len(r.unique_components),
            "errors": len(r.errors),
        },
        "ecosystem_breakdown": dict(r.ecosystem_counts.most_common()),
        "most_shared_components": [
            {"component": name, "project_count": count}
            for name, count in r.component_frequency.most_common(25) if count > 1
        ],
        "per_org": {
            org: stats for org, stats in sorted(r.org_stats.items())
        },
        "missing_version": [
            {"org": org, "project": proj, "component": name}
            for org, proj, name in r.missing_version
        ],
        "errors": [
            {"org": org, "project": proj, "project_id": pid, "code": code, "reason": reason}
            for org, proj, pid, code, reason in r.errors
        ],
        "components": [
            {"org": org, "project": proj, "component": name, "version": version, "purl": purl, "ecosystem": eco}
            for org, proj, name, version, purl, eco in r.flat_rows
        ],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)


def build_csv_report(report, output_path):
    """Flattened bill of materials - one row per (org, project, component). This is the
    Group-level equivalent of Snyk's Organization-level 'Export as CSV' dependency list."""
    r = report
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["org", "project", "component", "version", "purl", "ecosystem"])
        writer.writerows(r.flat_rows)


def build_html_report(report, output_path):
    r = report
    total_orgs = len(r.org_stats)
    total_errors = len(r.errors)

    # Ecosystem breakdown (identity -> fixed categorical order, cycling if >8 ecosystems).
    eco_sorted = r.ecosystem_counts.most_common()
    eco_color = {}
    for i, (eco, _) in enumerate(eco_sorted):
        eco_color[eco] = _ECOSYSTEM_HUES[i % len(_ECOSYSTEM_HUES)]
    max_eco = eco_sorted[0][1] if eco_sorted else 1
    eco_html = _bar_rows(eco_sorted, max_eco, lambda label: eco_color[label])
    eco_legend = "".join(
        f'<span class="legend-chip"><span class="swatch" style="background:{eco_color[e]}"></span>{_esc(e)}</span>'
        for e, _ in eco_sorted
    )

    # Most-shared components (magnitude -> single sequential hue).
    top_shared = [p for p in r.component_frequency.most_common(15) if p[1] > 1]
    max_shared = top_shared[0][1] if top_shared else 1
    shared_html = _bar_rows(top_shared, max_shared, lambda _label: "#2a78d6") if top_shared else \
        '<p class="muted">No component appears in more than one project.</p>'

    # Per-org table.
    org_rows = "".join(
        f"""<tr>
              <td>{_esc(org)}</td>
              <td class="num">{stats['projects']}</td>
              <td class="num">{stats['components']}</td>
              <td class="num">{'<span class="status-critical">' + str(stats['errors']) + '</span>' if stats['errors'] else '0'}</td>
            </tr>"""
        for org, stats in sorted(r.org_stats.items())
    )

    # Missing-version data-quality flags.
    if r.missing_version:
        missing_rows = "".join(
            f"<tr><td>{_esc(org)}</td><td>{_esc(proj)}</td><td>{_esc(name)}</td></tr>"
            for org, proj, name in r.missing_version[:50]
        )
        missing_section = f"""
        <h2><span class="status-icon warning">&#9888;</span> Components with no resolved version ({len(r.missing_version)})</h2>
        <p class="muted">A missing version means Snyk could not resolve that dependency's version from the manifest
           (e.g. inherited from a parent POM) &mdash; these components will not be checked against known
           vulnerabilities. Showing up to 50.</p>
        <table>
          <thead><tr><th>Org</th><th>Project</th><th>Component</th></tr></thead>
          <tbody>{missing_rows}</tbody>
        </table>"""
    else:
        missing_section = '<h2><span class="status-icon good">&#10003;</span> Components with no resolved version</h2><p class="muted">None found.</p>'

    # Errors table.
    if r.errors:
        error_rows = "".join(
            f"<tr><td>{_esc(org)}</td><td>{_esc(proj)}</td><td>{_esc(pid)}</td><td>{_esc(code)}</td><td>{_esc(reason)}</td></tr>"
            for org, proj, pid, code, reason in r.errors
        )
        error_section = f"""
        <h2><span class="status-icon critical">&#10060;</span> Generation errors ({total_errors})</h2>
        <table>
          <thead><tr><th>Org</th><th>Project</th><th>Project ID</th><th>Code</th><th>Reason</th></tr></thead>
          <tbody>{error_rows}</tbody>
        </table>"""
    else:
        error_section = '<h2><span class="status-icon good">&#10003;</span> Generation errors</h2><p class="muted">None &mdash; every eligible project produced an SBOM.</p>'

    # Project tree LINKS, grouped by org - not embedded trees. Keeps this file's
    # size proportional to project count (a short link line each), not to the
    # combined size of every dependency graph in the Group.
    links_by_org = collections.defaultdict(list)
    for org_label, project_name, tree_relpath, node_count in r.project_tree_index:
        links_by_org[org_label].append(
            f"""<div class="project-link-row">
                  <a href="{_esc(tree_relpath)}" target="_blank">{_esc(project_name)}</a>
                  <span class="muted">({node_count} components)</span>
                </div>"""
        )

    if links_by_org:
        org_sections = "".join(
            f"""<details class="org-node">
                  <summary>{_esc(org_label)} <span class="muted">({len(rows)} projects)</span></summary>
                  {''.join(rows)}
                </details>"""
            for org_label, rows in sorted(links_by_org.items())
        )
        tree_section = f"""
        <h2>Browse by project</h2>
        <p class="muted">Each project's dependency tree is its own page (reconstructed from that project's SBOM
           component graph), linked below rather than embedded here &mdash; keeps this report small no matter
           how many projects the Group has.</p>
        {org_sections}"""
    else:
        tree_section = ""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Group SBOM Report &mdash; {_esc(r.group_id)}</title>
<style>{_PAGE_CSS}</style>
</head>
<body>
<div class="viz-root">
  <h1>Group SBOM Report</h1>
  <div class="subtitle">Group {_esc(r.group_id)} &middot; format {_esc(r.sbom_format)} &middot; generated {_esc(r.generated_at)}</div>

  <div class="stat-tiles">
    <div class="tile"><div class="value">{total_orgs}</div><div class="label">Orgs scanned</div></div>
    <div class="tile"><div class="value">{r.total_projects}</div><div class="label">SBOMs generated</div></div>
    <div class="tile"><div class="value">{len(r.unique_components)}</div><div class="label">Unique components</div></div>
    <div class="tile"><div class="value">{total_errors}</div><div class="label">Errors</div></div>
  </div>

  <h2>Dependencies by ecosystem</h2>
  <div class="legend">{eco_legend}</div>
  {eco_html}

  <h2>Most widely shared components</h2>
  <p class="muted">Appears in more than one project &mdash; a vulnerability here has the widest blast radius across the Group.</p>
  {shared_html}

  <h2>Per-org summary</h2>
  <table>
    <thead><tr><th>Org</th><th class="num">Projects</th><th class="num">Components</th><th class="num">Errors</th></tr></thead>
    <tbody>{org_rows}</tbody>
  </table>

  {missing_section}

  {error_section}

  {tree_section}
</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html_doc)


# ---------------------------------------------------------------------------
# Work item processing - runs in worker threads. Each worker only does network
# I/O and its own file writes (each to a unique path); no shared mutable state
# is touched here, so no locks are needed. Aggregate bookkeeping (ReportData)
# happens back in the main thread as results complete.
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class WorkResult:
    org_label: str
    project_name: str
    project_id: str
    sbom: Optional[dict] = None
    error_code: Optional[int] = None
    error_reason: Optional[str] = None
    resumed: bool = False
    tree_relpath: Optional[str] = None
    tree_nodes: Optional[int] = None


def process_project(item, token, sbom_format, output_dir, resume, build_tree):
    org_id, org_label, project_id, project_name = item
    file_path = sbom_file_path(output_dir, org_label, project_name, project_id, sbom_format)
    resumed = False

    if resume and os.path.exists(file_path):
        try:
            with open(file_path) as f:
                sbom = json.load(f)
            resumed = True
        except (json.JSONDecodeError, OSError):
            sbom = None  # corrupt/partial file from an earlier interrupted run - regenerate
    else:
        sbom = None

    if sbom is None:
        try:
            sbom = generate_sbom(org_id, project_id, sbom_format, token)
        except urllib.error.HTTPError as e:
            return WorkResult(org_label=org_label, project_name=project_name, project_id=project_id,
                               error_code=e.code, error_reason=e.reason)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            json.dump(sbom, f, indent=2)

    tree_relpath, tree_nodes = None, None
    if build_tree:
        result = write_project_tree_file(sbom, org_label, project_name, project_id, output_dir)
        if result:
            tree_relpath, tree_nodes = result

    return WorkResult(org_label=org_label, project_name=project_name, project_id=project_id,
                       sbom=sbom, resumed=resumed, tree_relpath=tree_relpath, tree_nodes=tree_nodes)


def main():
    parser = argparse.ArgumentParser(
        description="Generate an SBOM for every eligible project in every org in a Snyk Group. "
                    "Writes one file per project - does not merge into a single document."
    )
    parser.add_argument("--groupId", "-g", required=True, help="Snyk Group ID")
    parser.add_argument("--format", "-f", default="cyclonedx1.4+json", choices=SUPPORTED_FORMATS,
                        help="SBOM format (default: cyclonedx1.4+json)")
    parser.add_argument("--outputDir", "-d", default="sboms", help="Local output directory (default: sboms)")
    parser.add_argument("--dryRun", action="store_true",
                        help="List orgs/projects that would be processed, without calling the SBOM endpoint")
    parser.add_argument("--report", action="store_true",
                        help="Also write an aggregate report in --outputDir: ecosystem breakdown, "
                             "most-shared components, per-org summary, missing-version flags, and errors.")
    parser.add_argument("--reportFormat", default="html",
                        help="Comma-separated: html, json, csv (default: html). "
                             "html = dashboard + linked per-project dependency-tree pages. "
                             "json = same aggregate analytics plus the full flat component list. "
                             "csv = flattened bill of materials, one row per (org, project, component).")
    parser.add_argument("--concurrency", "-c", type=int, default=8,
                        help="Parallel workers for SBOM fetches (default: 8). Raise cautiously - "
                             "this is shared API rate limit, not local compute.")
    parser.add_argument("--force", action="store_true",
                        help="Regenerate every SBOM even if its file already exists on disk. "
                             "Default behavior resumes: existing files are reused, not re-fetched - "
                             "safe to re-run the same command after a crash or interruption.")
    args = parser.parse_args()
    report_formats = [f.strip().lower() for f in args.reportFormat.split(",") if f.strip()]
    invalid_formats = set(report_formats) - {"html", "json", "csv"}
    if invalid_formats:
        print(f"Invalid --reportFormat value(s): {', '.join(invalid_formats)}. Choose from: html, json, csv")
        sys.exit(1)
    if args.concurrency < 1:
        print("--concurrency must be >= 1")
        sys.exit(1)

    token = os.getenv("SNYK_API_TOKEN")
    if not token:
        print("Could not find Snyk API key set as SNYK_API_TOKEN environment variable - exiting")
        sys.exit(1)

    print(f"Listing orgs in group {args.groupId}...")
    try:
        orgs = list_orgs_in_group(args.groupId, token)
    except urllib.error.HTTPError as e:
        print(f"Failed to list orgs for group {args.groupId}: {e.code} {e.reason}")
        sys.exit(1)
    print(f"Found {len(orgs)} org(s) in group.\n")

    # Phase 1 (concurrent): enumerate every eligible project up front. One org's
    # project list is independent of another's, so this uses the same bounded
    # worker pool as Phase 2 rather than listing orgs one at a time.
    def list_org(org):
        org_id = org["id"]
        org_label = safe_name(org.get("attributes", {}).get("slug") or org.get("attributes", {}).get("name") or org_id)
        try:
            projects = list_projects_in_org(org_id, token)
            return org_id, org_label, projects, None
        except urllib.error.HTTPError as e:
            return org_id, org_label, None, e

    work_items = []  # (org_id, org_label, project_id, project_name)
    org_results = {}  # org_label -> eligible count, for ordered printing
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for org_id, org_label, projects, error in pool.map(list_org, orgs):
            if error is not None:
                print(f"Failed to list projects for org {org_label} ({org_id}): {error.code} {error.reason}")
                continue

            org_eligible = 0
            for project in projects:
                attrs = project.get("attributes", {})
                if attrs.get("type") in EXCLUDED_PROJECT_TYPES:
                    continue
                org_eligible += 1
                work_items.append((org_id, org_label, project["id"], attrs.get("name", project["id"])))
            org_results[org_label] = org_eligible

    for org_label, org_eligible in sorted(org_results.items()):
        print(f"  {org_label}: {org_eligible} eligible project(s)")

    print(f"\nTotal eligible projects across {len(orgs)} org(s): {len(work_items)}\n")

    if args.dryRun:
        for org_id, org_label, project_id, project_name in work_items:
            print(f"  [dry-run] {org_label} / {project_name}")
        return

    # Phase 2 (concurrent): fetch/resume + write each project's SBOM.
    report = ReportData(args.groupId, args.format) if args.report else None
    build_tree = bool(report and "html" in report_formats)
    total_written = 0
    total_resumed = 0
    total_errors = 0
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [
            pool.submit(process_project, item, token, args.format, args.outputDir, not args.force, build_tree)
            for item in work_items
        ]
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            result = future.result()

            if result.error_code is not None:
                print(f"  FAILED  {result.org_label}/{result.project_name}: {result.error_code} {result.error_reason}")
                total_errors += 1
                if report:
                    report.record_error(result.org_label, result.project_name, result.project_id,
                                         result.error_code, result.error_reason)
            else:
                tag = "resumed" if result.resumed else "wrote  "
                print(f"  {tag} {result.org_label}/{result.project_name}")
                total_written += 1
                if result.resumed:
                    total_resumed += 1
                if report:
                    report.record_sbom(result.org_label, result.project_name, result.sbom)
                    if result.tree_relpath:
                        report.record_tree(result.org_label, result.project_name, result.tree_relpath, result.tree_nodes)

            if i % 100 == 0 or i == len(work_items):
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                remaining = len(work_items) - i
                eta = remaining / rate if rate > 0 else 0
                print(f"  --- progress: {i}/{len(work_items)} | {elapsed:.0f}s elapsed | "
                      f"~{eta:.0f}s remaining ---")

    print(f"\nDone. Orgs: {len(orgs)} | eligible projects: {len(work_items)} | "
          f"SBOMs written: {total_written} (resumed: {total_resumed}) | errors: {total_errors}")

    if report:
        if "html" in report_formats:
            path = os.path.join(args.outputDir, "report.html")
            build_html_report(report, path)
            print(f"Report (html): {path}")
        if "json" in report_formats:
            path = os.path.join(args.outputDir, "report.json")
            build_json_report(report, path)
            print(f"Report (json): {path}")
        if "csv" in report_formats:
            path = os.path.join(args.outputDir, "report.csv")
            build_csv_report(report, path)
            print(f"Report (csv):  {path}")


if __name__ == "__main__":
    main()

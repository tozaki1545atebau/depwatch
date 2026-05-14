"""Builds and renders a simple dependency graph showing which packages
depend on which, based on installed package metadata."""

from __future__ import annotations

import importlib.metadata as im
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DependencyNode:
    name: str
    version: str
    requires: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "requires": self.requires,
        }


def _normalise(name: str) -> str:
    """Lowercase and replace underscores/hyphens for consistent lookup."""
    return name.lower().replace("-", "_").replace(" ", "_")


def _extract_dep_name(requirement: str) -> str:
    """Strip version specifiers and extras from a requirement string."""
    for sep in (">", "<", "=", "!", "[", ";", " "):
        requirement = requirement.split(sep)[0]
    return requirement.strip()


def build_graph(package_names: Optional[List[str]] = None) -> Dict[str, DependencyNode]:
    """Return a mapping of normalised package name -> DependencyNode.

    If *package_names* is given only those packages (and their direct
    dependencies that are also installed) are included; otherwise every
    installed distribution is included.
    """
    all_dists: Dict[str, im.Distribution] = {
        _normalise(d.metadata["Name"]): d for d in im.distributions()
    }

    if package_names is not None:
        keys = {_normalise(n) for n in package_names}
    else:
        keys = set(all_dists.keys())

    graph: Dict[str, DependencyNode] = {}
    for key in keys:
        dist = all_dists.get(key)
        if dist is None:
            continue
        name = dist.metadata["Name"] or key
        version = dist.metadata["Version"] or "unknown"
        raw_requires = dist.requires or []
        requires = [
            _extract_dep_name(r)
            for r in raw_requires
            if "; extra ==" not in r  # skip optional extras
        ]
        graph[key] = DependencyNode(name=name, version=version, requires=requires)

    return graph


def render_text(graph: Dict[str, DependencyNode]) -> str:
    """Render the dependency graph as a human-readable text tree."""
    if not graph:
        return "No packages found.\n"

    lines = ["Dependency Graph", "=" * 40]
    for node in sorted(graph.values(), key=lambda n: n.name.lower()):
        lines.append(f"  {node.name} ({node.version})")
        for dep in sorted(node.requires):
            lines.append(f"    └─ {dep}")
    lines.append("")
    return "\n".join(lines)


def render_json(graph: Dict[str, DependencyNode]) -> list:
    """Return a JSON-serialisable list of dependency nodes."""
    return [node.as_dict() for node in sorted(graph.values(), key=lambda n: n.name.lower())]

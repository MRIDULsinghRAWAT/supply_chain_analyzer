"""
Dependency Graph — models package relationships, analyses depth/cycles,
and renders ASCII visualizations.
"""

import json
import os
from collections import defaultdict, deque


class DependencyGraph:
    """
    Directed graph of package dependencies.

    Nodes are package names (lowercase strings).
    An edge A → B means "A depends on B".

    Attributes
    ----------
    adjacency : dict[str, set[str]]
        Forward adjacency list (package → its dependencies).
    reverse : dict[str, set[str]]
        Reverse adjacency list (package → packages that depend on it).
    metadata : dict[str, dict]
        Per-node metadata (version, type, depth, is_direct).
    project_name : str
        Root project name shown at the top of the tree.
    """

    def __init__(self, project_name="project"):
        self.adjacency = defaultdict(set)
        self.reverse = defaultdict(set)
        self.metadata = {}
        self.project_name = project_name
        self._known_deps = None

    # ------------------------------------------------------------------
    # Building the graph
    # ------------------------------------------------------------------

    def build_from_dependencies(self, dependencies, ecosystem=None, known_deps_path=None):
        """
        Build the graph from a parsed dependency list.

        Parameters
        ----------
        dependencies : list[dict]
            Each dict has at least ``name`` and ``version`` keys.
        ecosystem : str, optional
            ``"python"`` or ``"npm"``.
        known_deps_path : str, optional
            Path to ``known_deps.json``.  Defaults to ``data/known_deps.json``
            relative to the project root.
        """
        # Load known transitive deps metadata
        self._load_known_deps(known_deps_path)

        eco_key = ecosystem or "python"
        known = self._known_deps.get(eco_key, {}) if self._known_deps else {}

        # Phase 1: register every declared dependency as a direct node
        for dep in dependencies:
            name = dep["name"].lower()
            version = dep.get("version", "unknown")
            dep_type = dep.get("type", "direct")

            self._add_node(name, version=version, dep_type=dep_type, is_direct=True)

        # Phase 2: expand transitive deps from known metadata
        visited = set()
        queue = deque(self.get_direct_deps())

        while queue:
            pkg = queue.popleft()
            if pkg in visited:
                continue
            visited.add(pkg)

            sub_deps = known.get(pkg, [])
            for sub in sub_deps:
                sub = sub.lower()
                self.adjacency[pkg].add(sub)
                self.reverse[sub].add(pkg)

                if sub not in self.metadata:
                    self._add_node(sub, version="transitive", dep_type="transitive", is_direct=False)

                if sub not in visited:
                    queue.append(sub)

        # Phase 3: compute depths via BFS from roots
        self._compute_depths()

    def add_edge(self, parent, child):
        """Manually add a dependency edge (parent depends on child)."""
        self.adjacency[parent].add(child)
        self.reverse[child].add(parent)

        # Ensure both nodes exist in metadata
        if parent not in self.metadata:
            self._add_node(parent)
        if child not in self.metadata:
            self._add_node(child)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def get_direct_deps(self):
        """Return list of direct dependency names."""
        return [name for name, meta in self.metadata.items() if meta.get("is_direct")]

    def get_transitive_deps(self):
        """Return list of transitive (non-direct) dependency names."""
        return [name for name, meta in self.metadata.items() if not meta.get("is_direct")]

    def get_all_packages(self):
        """Return sorted list of all package names in the graph."""
        return sorted(self.metadata.keys())

    def get_depth(self):
        """Return the maximum depth of the dependency tree."""
        if not self.metadata:
            return 0
        return max(meta.get("depth", 0) for meta in self.metadata.values())

    def get_dependencies_of(self, package):
        """Return the set of packages that *package* depends on."""
        return self.adjacency.get(package.lower(), set())

    def get_dependents_of(self, package):
        """Return the set of packages that depend on *package*."""
        return self.reverse.get(package.lower(), set())

    def get_most_depended_on(self):
        """Return (package_name, count) of the package with the most reverse deps."""
        if not self.reverse:
            return None, 0
        pkg = max(self.reverse, key=lambda p: len(self.reverse[p]))
        return pkg, len(self.reverse[pkg])

    def detect_cycles(self):
        """
        Detect cycles using DFS.  Returns a list of cycles, each cycle
        being a list of package names forming the loop.
        """
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {node: WHITE for node in self.metadata}
        cycles = []

        def dfs(node, path):
            color[node] = GRAY
            path.append(node)

            for neighbor in self.adjacency.get(node, set()):
                if neighbor not in color:
                    # Node not in metadata — skip
                    continue
                if color[neighbor] == GRAY:
                    # Found a cycle: extract it from path
                    cycle_start = path.index(neighbor)
                    cycles.append(list(path[cycle_start:]) + [neighbor])
                elif color[neighbor] == WHITE:
                    dfs(neighbor, path)

            path.pop()
            color[node] = BLACK

        for node in list(self.metadata.keys()):
            if color.get(node, WHITE) == WHITE:
                dfs(node, [])

        return cycles

    def get_dependency_chain(self, package):
        """
        Return all dependency chains from root(s) to *package* as a list
        of lists.  Each inner list is a path like
        ``["flask", "werkzeug", "markupsafe"]``.
        """
        package = package.lower()
        if package not in self.metadata:
            return []

        chains = []

        def _backtrack(node, path):
            parents = self.reverse.get(node, set())
            direct_parents = [p for p in parents if self.metadata.get(p, {}).get("is_direct")]
            non_direct_parents = [p for p in parents if not self.metadata.get(p, {}).get("is_direct")]

            if not parents or self.metadata.get(node, {}).get("is_direct"):
                chains.append(list(reversed(path)))
                return

            for parent in sorted(parents):
                if parent not in path:  # Avoid infinite loops
                    _backtrack(parent, path + [parent])

            if not any(p not in path for p in parents):
                # All parents already in path — we've hit a cycle, record what we have
                chains.append(list(reversed(path)))

        _backtrack(package, [package])
        return chains

    def get_statistics(self):
        """Return a dict with graph statistics."""
        direct = self.get_direct_deps()
        transitive = self.get_transitive_deps()
        most_dep_pkg, most_dep_count = self.get_most_depended_on()
        cycles = self.detect_cycles()

        return {
            "total_packages": len(self.metadata),
            "direct_dependencies": len(direct),
            "transitive_dependencies": len(transitive),
            "max_depth": self.get_depth(),
            "most_depended_on": {
                "package": most_dep_pkg,
                "dependents_count": most_dep_count
            } if most_dep_pkg else None,
            "cycles_detected": len(cycles),
            "cycles": cycles,
        }

    # ------------------------------------------------------------------
    # Visualization
    # ------------------------------------------------------------------

    def render_tree(self, max_depth=None):
        """
        Render the dependency tree as an ASCII string.

        Parameters
        ----------
        max_depth : int, optional
            Maximum depth to render.  ``None`` renders everything.

        Returns
        -------
        str
            Multi-line ASCII tree.
        """
        lines = [self.project_name]
        direct = sorted(self.get_direct_deps())

        for i, dep in enumerate(direct):
            is_last = (i == len(direct) - 1)
            prefix = "└── " if is_last else "├── "
            child_prefix = "    " if is_last else "│   "

            version = self.metadata[dep].get("version", "")
            dep_type = self.metadata[dep].get("dep_type", "")
            label = dep
            if version and version != "transitive":
                label += f" {version}"
            if dep_type and dep_type not in ("direct", "dependencies"):
                label += f" ({dep_type})"

            lines.append(f"{prefix}{label}")
            self._render_subtree(dep, child_prefix, lines, depth=1, max_depth=max_depth)

        return "\n".join(lines)

    def _render_subtree(self, node, prefix, lines, depth, max_depth):
        """Recursively render children of *node*."""
        if max_depth is not None and depth >= max_depth:
            children = sorted(self.adjacency.get(node, set()))
            if children:
                lines.append(f"{prefix}└── ... ({len(children)} transitive deps)")
            return

        children = sorted(self.adjacency.get(node, set()))
        for i, child in enumerate(children):
            is_last = (i == len(children) - 1)
            connector = "└── " if is_last else "├── "
            child_connector = "    " if is_last else "│   "

            version = self.metadata.get(child, {}).get("version", "")
            label = child
            if version and version != "transitive":
                label += f" {version}"
            else:
                label += " (transitive)"

            lines.append(f"{prefix}{connector}{label}")
            self._render_subtree(child, prefix + child_connector, lines,
                                 depth + 1, max_depth)

    def render_stats_box(self):
        """
        Render a bordered box with dependency graph statistics.

        Returns
        -------
        str
            Multi-line bordered text box.
        """
        stats = self.get_statistics()
        most = stats["most_depended_on"]
        most_str = f"{most['package']} ({most['dependents_count']}×)" if most else "N/A"
        cycles_str = "None" if stats["cycles_detected"] == 0 else f"{stats['cycles_detected']} found"

        rows = [
            ("Direct dependencies", str(stats["direct_dependencies"])),
            ("Transitive dependencies", str(stats["transitive_dependencies"])),
            ("Total packages", str(stats["total_packages"])),
            ("Max dependency depth", str(stats["max_depth"])),
            ("Most depended-on", most_str),
            ("Cycles detected", cycles_str),
        ]

        title = "DEPENDENCY GRAPH ANALYSIS"
        # Calculate box width
        content_width = max(len(title), max(len(f"  {r[0]}:  {r[1]}") for r in rows)) + 4
        content_width = max(content_width, 42)  # Minimum width

        lines = []
        lines.append("┌" + "─" * content_width + "┐")
        lines.append("│" + title.center(content_width) + "│")
        lines.append("├" + "─" * content_width + "┤")

        for label, value in rows:
            left = f"  {label}:"
            right = f"{value}  "
            padding = content_width - len(left) - len(right)
            lines.append("│" + left + " " * max(padding, 1) + right + "│")

        lines.append("└" + "─" * content_width + "┘")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self):
        """Return a JSON-serializable dict of the full graph."""
        return {
            "project_name": self.project_name,
            "statistics": self.get_statistics(),
            "nodes": {
                name: {
                    "version": meta.get("version", "unknown"),
                    "type": meta.get("dep_type", "unknown"),
                    "depth": meta.get("depth", 0),
                    "is_direct": meta.get("is_direct", False),
                    "depends_on": sorted(self.adjacency.get(name, set())),
                    "depended_on_by": sorted(self.reverse.get(name, set())),
                }
                for name, meta in sorted(self.metadata.items())
            },
            "tree_visualization": self.render_tree(max_depth=3),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_node(self, name, version="unknown", dep_type="unknown", is_direct=False):
        """Register a node in the metadata dict."""
        if name in self.metadata:
            # If upgrading from transitive to direct, mark as direct
            if is_direct:
                self.metadata[name]["is_direct"] = True
                if version != "transitive":
                    self.metadata[name]["version"] = version
                self.metadata[name]["dep_type"] = dep_type
            return

        self.metadata[name] = {
            "version": version,
            "dep_type": dep_type,
            "is_direct": is_direct,
            "depth": 0,
        }
        # Ensure adjacency entries exist
        if name not in self.adjacency:
            self.adjacency[name] = set()

    def _compute_depths(self):
        """BFS from root (direct deps = depth 0) to assign depth to all nodes."""
        queue = deque()
        for name in self.get_direct_deps():
            self.metadata[name]["depth"] = 0
            queue.append((name, 0))

        visited = set()
        while queue:
            node, depth = queue.popleft()
            if node in visited:
                continue
            visited.add(node)

            for child in self.adjacency.get(node, set()):
                if child in self.metadata and child not in visited:
                    child_depth = depth + 1
                    # Keep the shallowest depth if already set
                    if self.metadata[child]["depth"] == 0 and not self.metadata[child]["is_direct"]:
                        self.metadata[child]["depth"] = child_depth
                    self.metadata[child]["depth"] = min(
                        self.metadata[child]["depth"] or child_depth,
                        child_depth
                    ) if self.metadata[child]["depth"] > 0 else child_depth
                    queue.append((child, child_depth))

    def _load_known_deps(self, path=None):
        """Load the known transitive dependency metadata."""
        if self._known_deps is not None:
            return  # Already loaded

        if path is None:
            path = os.path.join(
                os.path.dirname(__file__), '../../data/known_deps.json'
            )

        try:
            with open(path, 'r') as f:
                self._known_deps = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._known_deps = {}

    def find_path_to(self, target):
        """Find the shortest dependency path from a direct dependency to target package."""
        target = target.lower()
        roots = self.get_direct_deps()
        if target in roots:
            return [target]

        queue = deque([[root] for root in roots])
        visited = set(roots)
        while queue:
            path = queue.popleft()
            current = path[-1]
            if current == target:
                return path

            for child in self.adjacency.get(current, set()):
                if child not in visited:
                    visited.add(child)
                    queue.append(path + [child])
        return []

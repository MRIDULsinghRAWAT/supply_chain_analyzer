import json
import os
import Levenshtein


class TyposquattingScanner:
    """
    Multi-technique typosquatting detector.

    Detection techniques:
      1. Levenshtein distance (edit distance 1–2)
      2. Separator confusion (dash vs underscore vs none)
      3. Character swap / repetition
      4. Combosquatting (popular name embedded with short prefix/suffix)
      5. Homoglyph substitution (visually similar characters)
      6. Version-suffix squatting (popular name + single digit)
    """

    # Map of visually similar characters used in homoglyph attacks
    HOMOGLYPH_MAP = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '9': 'g',
        'o': '0', 'l': '1', 'e': '3', 'a': '4', 's': '5',
        't': '7', 'b': '8', 'g': '9',
        'rn': 'm', 'vv': 'w', 'cl': 'd', 'nn': 'm',
    }

    # Single-char homoglyphs for normalization
    HOMOGLYPH_SINGLES = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '9': 'g',
    }

    # Multi-char homoglyphs (order matters: check longer patterns first)
    HOMOGLYPH_PAIRS = [
        ('rn', 'm'), ('vv', 'w'), ('cl', 'd'), ('nn', 'm'),
    ]

    def __init__(self):
        """Load popular packages from data folder."""
        data_path = os.path.join(os.path.dirname(__file__), '../../data/popular_packages.json')
        with open(data_path, 'r') as f:
            raw = json.load(f)

        # Support both the new ecosystem-aware format and the legacy flat-array format
        if isinstance(raw, dict):
            self._packages_by_ecosystem = {
                "python": list(set(raw.get("python", []) + raw.get("shared", []))),
                "npm": list(set(raw.get("npm", []) + raw.get("shared", []))),
            }
            # Build a combined set for fallback / ecosystem-agnostic use
            all_pkgs = set()
            for pkgs in raw.values():
                all_pkgs.update(pkgs)
            self._all_packages = list(all_pkgs)
        else:
            # Legacy flat array
            self._all_packages = list(set(raw))
            self._packages_by_ecosystem = {
                "python": self._all_packages,
                "npm": self._all_packages,
            }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, dependencies, reporter=None, ecosystem=None):
        """
        Scan a list of dependencies for potential typosquatting.

        Parameters
        ----------
        dependencies : list[dict]
            Each dict must have at least a ``"name"`` key.
        reporter : ConsoleReporter, optional
            For live-stream progress output.
        ecosystem : str, optional
            ``"python"`` or ``"npm"``.  When provided the scanner checks
            against only the relevant package list.  Falls back to the
            combined list when *None*.

        Returns
        -------
        list[dict]
            Alert dicts with keys: type, package, similar_to, technique,
            confidence, severity, message.
        """
        popular = self._resolve_popular(ecosystem)
        popular_set = set(popular)
        # Pre-compute normalized forms for separator & homoglyph checks
        popular_normalized_sep = {self._normalize_separators(p): p for p in popular}
        popular_normalized_homo = {self._normalize_homoglyphs(p): p for p in popular}

        alerts = []
        seen = set()  # Avoid duplicate alerts for the same (package, similar_to)

        for dep in dependencies:
            name = dep['name'].lower()

            if reporter:
                reporter.print_stream(f"Live Stream: Scanning packet '{name}' for typosquatting...")

            # Skip if the package IS a known popular package
            if name in popular_set:
                continue

            for popular_name in popular:
                key = (name, popular_name)
                if key in seen:
                    continue

                alert = self._check_all_techniques(name, popular_name,
                                                   popular_normalized_sep,
                                                   popular_normalized_homo)
                if alert:
                    seen.add(key)
                    alerts.append(alert)

        if reporter:
            reporter.clear_stream()

        return alerts

    # ------------------------------------------------------------------
    # Detection techniques
    # ------------------------------------------------------------------

    def _check_all_techniques(self, name, popular_name,
                              popular_norm_sep, popular_norm_homo):
        """Run all detection techniques; return the first (highest-priority) match.
        
        Order matters: specific techniques run before the broad Levenshtein
        catch-all so that precise labels like 'character_swap' take priority
        over a generic 'levenshtein_distance_2'.
        """
        checks = [
            self._check_separator_confusion,
            self._check_character_swap,
            self._check_repeated_chars,
            self._check_homoglyph,
            self._check_version_suffix,
            self._check_combosquatting,
            self._check_levenshtein,  # broadest — runs last
        ]
        for check_fn in checks:
            result = check_fn(name, popular_name,
                              popular_norm_sep, popular_norm_homo)
            if result:
                return result
        return None

    # --- 1. Levenshtein distance -------------------------------------------

    def _check_levenshtein(self, name, popular_name, _sep, _homo):
        distance = Levenshtein.distance(name, popular_name)
        if distance == 1:
            return self._make_alert(
                name, popular_name,
                technique="levenshtein_distance_1",
                confidence="HIGH",
                severity="HIGH",
                message=(f"Edit distance 1: '{name}' is 1 character away "
                         f"from popular package '{popular_name}'"),
            )
        if distance == 2:
            return self._make_alert(
                name, popular_name,
                technique="levenshtein_distance_2",
                confidence="MEDIUM",
                severity="MEDIUM",
                message=(f"Edit distance 2: '{name}' is 2 characters away "
                         f"from popular package '{popular_name}'"),
            )
        return None

    # --- 2. Separator confusion --------------------------------------------

    def _check_separator_confusion(self, name, popular_name, popular_norm_sep, _homo):
        # Only relevant if the name and popular name differ
        if name == popular_name:
            return None
        norm_name = self._normalize_separators(name)
        # Check if normalized form matches any popular normalized form
        if norm_name in popular_norm_sep:
            matched_popular = popular_norm_sep[norm_name]
            if name != matched_popular:
                return self._make_alert(
                    name, matched_popular,
                    technique="separator_confusion",
                    confidence="HIGH",
                    severity="HIGH",
                    message=(f"Separator confusion: '{name}' normalizes to the "
                             f"same name as '{matched_popular}' when dashes, "
                             f"underscores and dots are removed"),
                )
        return None

    # --- 3. Character swap (adjacent transposition) ------------------------

    def _check_character_swap(self, name, popular_name, _sep, _homo):
        if len(name) != len(popular_name):
            return None
        diffs = [(i, name[i], popular_name[i])
                 for i in range(len(name)) if name[i] != popular_name[i]]
        if len(diffs) == 2:
            i, j = diffs[0][0], diffs[1][0]
            if j == i + 1 and diffs[0][1] == diffs[1][2] and diffs[0][2] == diffs[1][1]:
                return self._make_alert(
                    name, popular_name,
                    technique="character_swap",
                    confidence="HIGH",
                    severity="HIGH",
                    message=(f"Adjacent character swap: '{name}' has characters "
                             f"swapped compared to '{popular_name}'"),
                )
        return None

    # --- 4. Repeated characters --------------------------------------------

    def _check_repeated_chars(self, name, popular_name, _sep, _homo):
        # Check if removing one duplicate adjacent character yields the popular name
        if abs(len(name) - len(popular_name)) != 1:
            return None
        # Try removing repeated chars from the longer string to see if it matches the shorter
        longer, shorter = (name, popular_name) if len(name) > len(popular_name) else (popular_name, name)
        for i in range(len(longer) - 1):
            if longer[i] == longer[i + 1]:
                candidate = longer[:i] + longer[i + 1:]
                if candidate == shorter:
                    return self._make_alert(
                        name, popular_name,
                        technique="repeated_character",
                        confidence="MEDIUM",
                        severity="MEDIUM",
                        message=(f"Repeated character: '{name}' has a duplicated "
                                 f"character compared to '{popular_name}'"),
                    )
        return None

    # --- 5. Homoglyph substitution -----------------------------------------

    def _check_homoglyph(self, name, popular_name, _sep, popular_norm_homo):
        if name == popular_name:
            return None
        norm = self._normalize_homoglyphs(name)
        if norm in popular_norm_homo:
            matched_popular = popular_norm_homo[norm]
            if name != matched_popular:
                return self._make_alert(
                    name, matched_popular,
                    technique="homoglyph",
                    confidence="CRITICAL",
                    severity="CRITICAL",
                    message=(f"Homoglyph attack: '{name}' uses visually similar "
                             f"characters to mimic '{matched_popular}'"),
                )
        return None

    # --- 6. Version suffix squatting ---------------------------------------

    def _check_version_suffix(self, name, popular_name, _sep, _homo):
        # e.g. "requests2" → "requests" + "2"
        if len(name) == len(popular_name) + 1 and name[-1].isdigit():
            if name[:-1] == popular_name:
                return self._make_alert(
                    name, popular_name,
                    technique="version_suffix",
                    confidence="HIGH",
                    severity="HIGH",
                    message=(f"Version suffix squatting: '{name}' is "
                             f"'{popular_name}' with a trailing digit"),
                )
        return None

    # --- 7. Combosquatting (substring with short prefix/suffix) ------------

    def _check_combosquatting(self, name, popular_name, _sep, _homo):
        # Only consider popular names long enough to be meaningful (>=4 chars)
        if len(popular_name) < 4:
            return None
        # Skip if the name is the same length or shorter (those are caught above)
        if len(name) <= len(popular_name):
            return None
        # Check if popular_name is a substring, with a short extra part (≤ 6 chars added)
        extra = len(name) - len(popular_name)
        if extra > 6:
            return None

        if name.startswith(popular_name) or name.endswith(popular_name):
            # Ignore if the extra part is just a separator
            remainder = name.replace(popular_name, '', 1)
            if remainder and remainder not in ('-', '_', '.'):
                return self._make_alert(
                    name, popular_name,
                    technique="combosquatting",
                    confidence="LOW",
                    severity="MEDIUM",
                    message=(f"Combosquatting: '{name}' embeds the popular "
                             f"package name '{popular_name}'"),
                )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_separators(name):
        """Strip dashes, underscores, and dots to a canonical form."""
        return name.replace('-', '').replace('_', '').replace('.', '').lower()

    @classmethod
    def _normalize_homoglyphs(cls, name):
        """Replace visually similar characters with their canonical form."""
        result = name.lower()
        # Multi-char replacements first
        for src, dst in cls.HOMOGLYPH_PAIRS:
            result = result.replace(src, dst)
        # Single-char replacements
        out = []
        for ch in result:
            out.append(cls.HOMOGLYPH_SINGLES.get(ch, ch))
        return ''.join(out)

    @staticmethod
    def _make_alert(package, similar_to, *, technique, confidence, severity, message):
        return {
            "type": "TYPOSQUATTING",
            "package": package,
            "similar_to": similar_to,
            "technique": technique,
            "confidence": confidence,
            "severity": severity,
            "message": message,
        }

    def _resolve_popular(self, ecosystem):
        """Return the correct list of popular packages for the given ecosystem."""
        if ecosystem and ecosystem in self._packages_by_ecosystem:
            return self._packages_by_ecosystem[ecosystem]
        return self._all_packages
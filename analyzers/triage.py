"""Triage for Semgrep findings: new vs pre-existing, then P1/P2/P3.

The SAST counterpart of sca-triage's src/triage.js. Everything here is a pure
function: no network, no files, no scanner calls.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Set

# "@@ -12,4 +12,6 @@ optional context" -> the new file's hunk starts at line 12
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(patch: Optional[str]) -> Optional[Set[int]]:
    """Return the line numbers (in the new file) that a unified diff adds or changes.

    A changed line shows up in a diff as a removed line plus an added one, so
    every "+" line counts. None means "unknown": no patch, or one that does not
    parse. Callers treat unknown as "every line is new", so a bad diff can
    only over-report findings, never hide one.
    """
    if not isinstance(patch, str) or not patch:
        return None
    lines: Set[int] = set()
    line = None
    for row in patch.splitlines():
        header = HUNK_HEADER.match(row)
        if header:
            line = int(header.group(1))
        elif line is None:
            return None  # text before the first hunk header
        elif row.startswith("+"):
            lines.add(line)
            line += 1
        elif row.startswith(" ") or row == "":
            line += 1  # unchanged context line
        elif row.startswith(("-", "\\")):
            continue  # removed line, or "\ No newline at end of file"
        else:
            return None
    return lines


def changed_lines(entry: Dict[str, Any]) -> Optional[Set[int]]:
    """Lines the pull request added or changed in one entry of GitHub's PR files list.

    GitHub leaves out `patch` for very large diffs, which gives None (unknown).
    A file that was only renamed has no patch either, but nothing in it changed.
    """
    if entry.get("status") == "renamed" and entry.get("changes") == 0:
        return set()
    return added_lines(entry.get("patch"))

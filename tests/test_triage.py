"""Triage: which findings a pull request introduced, and how urgent they are. Offline only."""
import pytest

import app
from analyzers.triage import added_lines, changed_lines

# Two hunks: line 2 changed, line 3 added, then line 22 changed further down.
PATCH = """@@ -1,4 +1,5 @@
 import os
-x = 1
+x = 2
+y = 3

 def f():
@@ -20,2 +21,2 @@ def g():
     a = 1
-    b = 2
+    b = 3
\\ No newline at end of file"""


def test_added_lines_reads_every_hunk():
    assert added_lines(PATCH) == {2, 3, 22}


def test_new_file_is_all_added_and_deletions_add_nothing():
    assert added_lines("@@ -0,0 +1,3 @@\n+a\n+b\n+c") == {1, 2, 3}
    assert added_lines("@@ -5,2 +5,1 @@\n keep\n-gone") == set()


@pytest.mark.parametrize('patch', [None, '', 42, 'Binary files differ', '@@ broken @@\n+x', '@@ -1 +1 @@\n*odd'])
def test_missing_or_unreadable_patch_is_unknown(patch):
    assert added_lines(patch) is None


def test_pure_rename_has_no_changed_lines():
    assert changed_lines({'filename': 'b.py', 'status': 'renamed', 'changes': 0}) == set()
    assert changed_lines({'filename': 'b.py', 'status': 'renamed', 'changes': 1, 'patch': '@@ -1 +1 @@\n-x\n+y'}) == {1}


def test_changed_file_list_keeps_each_files_changed_lines(monkeypatch):
    monkeypatch.setattr(app, '_get_json', lambda *a, **k: [
        {'filename': 'a.py', 'status': 'modified', 'patch': '@@ -1 +1 @@\n-x\n+y'},
        {'filename': 'big.py', 'status': 'modified'},
        {'filename': 'gone.py', 'status': 'removed', 'patch': '@@ -1 +0,0 @@\n-x'},
    ])
    assert app.list_changed_files('o', 'r', 1, 'fake', 1) == {'a.py': {1}, 'big.py': None}

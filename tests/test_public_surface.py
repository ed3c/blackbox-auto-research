from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_public_surface.py"
SPEC = importlib.util.spec_from_file_location("check_public_surface", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicSurfaceTests(unittest.TestCase):
    def _root(self) -> Path:
        root = Path(tempfile.mkdtemp())
        for name in ("README.md", "AGENTS.md", "SECURITY.md"):
            (root / name).write_text(f"# {name}\n", encoding="utf-8")
        (root / "LICENSE").write_text(
            "Apache License\nVersion 2.0, January 2004\n",
            encoding="utf-8",
        )
        return root

    def test_good_tree_passes(self) -> None:
        root = self._root()
        (root / "guide.md").write_text("[readme](README.md)\n", encoding="utf-8")
        self.assertEqual(MODULE.check(root), [])

    def test_wrong_license_turns_gate_red(self) -> None:
        root = self._root()
        (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
        failures = MODULE.check(root)
        self.assertIn("LICENSE is not recognized as Apache-2.0", failures)

    def test_private_path_turns_gate_red(self) -> None:
        root = self._root()
        (root / "leak.txt").write_text("/" + "Users/example/private\n", encoding="utf-8")
        failures = MODULE.check(root)
        self.assertTrue(any("private literal" in item for item in failures), failures)

    def test_broken_link_turns_gate_red(self) -> None:
        root = self._root()
        (root / "guide.md").write_text("[missing](nope.md)\n", encoding="utf-8")
        failures = MODULE.check(root)
        self.assertTrue(any("broken local Markdown link" in item for item in failures), failures)


if __name__ == "__main__":
    unittest.main()

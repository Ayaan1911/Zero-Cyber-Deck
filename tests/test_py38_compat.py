"""Static Python 3.8 compatibility check (no 3.8 interpreter is required, none was available when this was written).

Guards against: syntax newer than 3.8, stdlib APIs added in 3.9+, and runtime-evaluated PEP 585/604 types.
"""
import _isolation  # noqa: F401
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = sorted(p for p in ROOT.rglob("*.py") if ".git" not in p.parts)

BANNED_ATTRS = {  # attribute name -> version that introduced it
    "removeprefix": "3.9", "removesuffix": "3.9", "is_relative_to": "3.9", "with_stem": "3.9", "lcm": "3.9",
    "hardlink_to": "3.10", "bit_count": "3.10", "pairwise": "3.10", "isjunction": "3.12", "batched": "3.12",
    "unparse": "3.9", "readlink": "3.9",
}
BANNED_KEYWORDS = {  # (callee attribute/name, keyword) -> version
    ("write_text", "newline"): "3.10", ("read_text", "newline"): "3.13", ("zip", "strict"): "3.10",
    ("dataclass", "slots"): "3.10", ("dataclass", "kw_only"): "3.10", ("walk", "top_down"): "3.12",
    ("rmtree", "onexc"): "3.12", ("copytree", "dirs_exist_ok"): "3.8-ok",
}
BANNED_NAMES = {"ExceptionGroup", "aiter", "anext", "tomllib", "Self"}
BUILTIN_GENERICS = {"list", "dict", "tuple", "set", "frozenset", "type"}


def _annotation_nodes(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            yield node.annotation
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            yield node.returns
        elif isinstance(node, ast.AnnAssign):
            yield node.annotation


def _has_future_annotations(tree):
    return any(isinstance(n, ast.ImportFrom) and n.module == "__future__" and any(a.name == "annotations" for a in n.names) for n in tree.body)


class Py38Tests(unittest.TestCase):
    def test_files_found(self):
        self.assertGreater(len(FILES), 8)

    def test_syntax_is_valid_for_python_3_8(self):
        for f in FILES:
            try:
                ast.parse(f.read_text(encoding="utf-8"), filename=str(f), feature_version=(3, 8))
            except SyntaxError as exc:
                self.fail(f"{f.relative_to(ROOT)}: not valid Python 3.8 syntax: {exc}")

    def test_no_newer_stdlib_apis(self):
        problems = []
        for f in FILES:
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in BANNED_ATTRS:
                    problems.append(f"{f.name}:{node.lineno} .{node.attr} (Python {BANNED_ATTRS[node.attr]}+)")
                if isinstance(node, ast.Name) and node.id in BANNED_NAMES:
                    problems.append(f"{f.name}:{node.lineno} {node.id}")
                if isinstance(node, ast.ImportFrom) and node.module in {"tomllib"}:
                    problems.append(f"{f.name}:{node.lineno} import {node.module}")
                if isinstance(node, ast.Call):
                    callee = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                    for kw in node.keywords:
                        version = BANNED_KEYWORDS.get((callee, kw.arg))
                        if version and version != "3.8-ok":
                            problems.append(f"{f.name}:{node.lineno} {callee}({kw.arg}=) (Python {version}+)")
        self.assertEqual(problems, [])

    def test_modern_type_syntax_is_never_evaluated_at_runtime(self):
        problems = []
        for f in FILES:
            tree = ast.parse(f.read_text(encoding="utf-8"))
            future = _has_future_annotations(tree)
            in_annotation = {id(n) for a in _annotation_nodes(tree) for n in ast.walk(a)}
            for node in ast.walk(tree):
                is_generic = isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in BUILTIN_GENERICS
                is_union = isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr) and any(
                    (isinstance(side, ast.Constant) and side.value is None) for side in (node.left, node.right))
                if (is_generic or is_union) and (id(node) not in in_annotation or not future):
                    problems.append(f"{f.relative_to(ROOT)}:{node.lineno} evaluated at runtime on 3.8")
        self.assertEqual(problems, [])

    def test_the_checker_catches_what_it_claims_to(self):
        bad = ast.parse("from pathlib import Path\nPath('x').write_text('a', newline='\\n')\nx = 'ab'.removeprefix('a')\ny: list[int] = []\n")
        hits = [n for n in ast.walk(bad) if isinstance(n, ast.Attribute) and n.attr in BANNED_ATTRS]
        calls = [n for n in ast.walk(bad) if isinstance(n, ast.Call) and any((getattr(n.func, "attr", ""), k.arg) in BANNED_KEYWORDS for k in n.keywords)]
        self.assertEqual((len(hits), len(calls)), (1, 1))


if __name__ == "__main__":
    unittest.main()

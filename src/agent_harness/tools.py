"""Tools the agent may call. Every path is confined to the workspace; risk levels drive the guardrails."""

import ast
import operator
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

READ, WRITE, EXEC = "read", "write", "exec"


class ToolError(Exception):
    """A tool refused or failed; the message goes back to the model as data."""


@dataclass
class Tool:
    name: str
    description: str
    params: dict  # JSON schema "properties"
    fn: Callable[..., str]
    risk: str = READ
    untrusted_output: bool = False  # output comes from outside (files, web): taints the session

    def schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {"type": "object", "properties": self.params, "required": list(self.params)},
            },
        }


class Workspace:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, path: str) -> Path:
        """The real path inside the workspace; refuses absolute paths, '..' and symlinks that escape."""
        if not isinstance(path, str) or not path or Path(path).is_absolute():
            raise ToolError("path must be relative to the workspace")
        real = (self.root / path).resolve()
        if real != self.root and self.root not in real.parents:
            raise ToolError("path escapes the workspace")
        return real


_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.FloorDiv: operator.floordiv,
}


def _calc(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int | float):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        if isinstance(node.op, ast.Pow) and abs(_calc(node.right)) > 100:
            raise ToolError("exponent too large")
        return _OPS[type(node.op)](_calc(node.left), _calc(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.operand))
    raise ToolError("only numbers and + - * / // % ** are allowed")


SANDBOX = """(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "{root}") (literal "/dev/null"))
(deny file-read* (subpath "/Users") (subpath "/Volumes"))
(allow file-read* (subpath "{root}"))
"""


def default_tools(ws: Workspace) -> list[Tool]:
    def read_file(path: str) -> str:
        p = ws.resolve(path)
        if not p.is_file():
            raise ToolError("no such file")
        return p.read_text(errors="replace")[:20_000]

    def write_file(path: str, content: str) -> str:
        p = ws.resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"wrote {len(content)} characters to {path}"

    def list_files(path: str = ".") -> str:
        p = ws.resolve(path)
        return "\n".join(sorted(str(x.relative_to(ws.root)) for x in p.rglob("*") if x.is_file())[:500])

    def calculate(expression: str) -> str:
        try:
            return str(_calc(ast.parse(expression, mode="eval").body))
        except (SyntaxError, ZeroDivisionError, OverflowError) as exc:
            raise ToolError(str(exc)) from None

    def shell(command: str) -> str:
        """macOS only: sandbox-exec with no network and writes only inside the workspace. Fails closed elsewhere."""
        if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
            raise ToolError("shell is disabled: no sandbox available on this system")
        profile = SANDBOX.format(root=str(ws.root).replace('"', ""))
        r = subprocess.run(
            ["sandbox-exec", "-p", profile, "/bin/sh", "-c", command],
            cwd=ws.root,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin", "HOME": str(ws.root)},
        )
        return f"exit {r.returncode}\n{(r.stdout + r.stderr)[:8000]}"

    path = {"path": {"type": "string", "description": "path relative to the workspace"}}
    return [
        Tool("read_file", "Read a text file from the workspace.", path, read_file, READ, untrusted_output=True),
        Tool("list_files", "List files in the workspace.", path, list_files, READ, untrusted_output=True),
        Tool("calculate", "Evaluate an arithmetic expression.", {"expression": {"type": "string"}}, calculate, READ),
        Tool(
            "write_file",
            "Write a text file in the workspace.",
            {**path, "content": {"type": "string"}},
            write_file,
            WRITE,
        ),
        Tool(
            "shell",
            "Run a shell command in a sandbox (no network, workspace only).",
            {"command": {"type": "string"}},
            shell,
            EXEC,
        ),
    ]

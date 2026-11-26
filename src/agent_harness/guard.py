"""Guardrails decided by code, never by the model.

- Tools not on the allow-list are refused.
- WRITE and EXEC tools need approval unless the policy pre-approves them.
- Once untrusted content (a file, a web page) is in the context, WRITE and EXEC always need approval:
  untrusted input + tools that change things is how prompt injection turns into damage.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from agent_harness.tools import EXEC, WRITE, Tool


@dataclass
class Policy:
    allowed: set[str] | None = None  # None = every registered tool
    auto_approve: set[str] = field(default_factory=set)  # risky tools approved in advance (clean session only)
    approve: Callable[[str, dict], bool] = lambda name, args: False  # human-in-the-loop; default deny

    def check(self, tool: Tool, args: dict, tainted: bool) -> str | None:
        """None if the call may run, else the reason it was blocked."""
        if self.allowed is not None and tool.name not in self.allowed:
            return f"tool {tool.name} is not allowed by policy"
        if tool.risk not in (WRITE, EXEC):
            return None
        if not tainted and tool.name in self.auto_approve:
            return None
        if self.approve(tool.name, args):
            return None
        why = "untrusted content is in context" if tainted else "it changes state"
        return f"{tool.name} needs human approval because {why}; approval was not given"

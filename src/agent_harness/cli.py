"""agent-harness run "task" --model qwen3.8:27b --workspace ./ws [--approve write_file] [--trace trace.jsonl]"""

import argparse
import json
import os

from agent_harness.guard import Policy
from agent_harness.loop import Budget, run
from agent_harness.model import OpenAIChat
from agent_harness.tools import Workspace, default_tools
from agent_harness.trace import Trace


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="agent-harness")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run one task")
    r.add_argument("task")
    r.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1"))
    r.add_argument("--model", default=os.getenv("AGENT_MODEL", "qwen3.8:27b"))
    r.add_argument("--workspace", default="./workspace")
    r.add_argument("--approve", action="append", default=[], help="pre-approve a risky tool (clean sessions only)")
    r.add_argument("--ask", action="store_true", help="ask on the terminal before every risky call")
    r.add_argument("--max-steps", type=int, default=12)
    r.add_argument("--trace")
    r.add_argument("--kill-switch", default=None, help="stop as soon as this file exists")
    a = p.parse_args(argv)
    model = OpenAIChat(a.base_url, a.model, os.getenv("OPENAI_API_KEY", "local"))
    ask = (
        (lambda n, args: input(f"Allow {n} {json.dumps(args)[:200]}? [y/N] ").strip().lower() == "y")
        if a.ask
        else (lambda n, args: False)
    )
    result = run(
        a.task,
        model,
        default_tools(Workspace(a.workspace)),
        Policy(auto_approve=set(a.approve), approve=ask),
        Budget(max_steps=a.max_steps),
        Trace(a.trace),
        a.kill_switch,
    )
    print(result.answer if result.status == "done" else f"STOPPED: {result.reason}")
    print(json.dumps(result.trace.summary()))
    return 0 if result.status == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())

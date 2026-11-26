# agent-harness

[![CI](https://github.com/akincenk/agent-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/akincenk/agent-harness/actions/workflows/ci.yml)

A small, tested harness for long-running LLM agents. The model proposes tool calls; plain Python code decides whether they run. It is written with the Python standard library only and works with any OpenAI-compatible endpoint, including a fully local model through [Ollama](https://ollama.com).

It covers the parts that make agents safe to leave running: loop budgets, failure handling, loop detection, a kill switch, guardrails against prompt injection, sandboxed tools, parallel sub-agents and a trace of every step.

## What the harness enforces

| Concern | How |
| --- | --- |
| Runaway loops | Budgets for steps, tool calls and wall time. The same call with the same arguments more than three times stops the run. |
| Failing tools | After 3 failed calls in a row the model is told to change approach; after 6 the run stops. |
| Emergency stop | A kill-switch file is checked before every model call. |
| Prompt injection | Tool output is labelled as untrusted data. Once untrusted content (a file) is in the context, tools that write or execute need human approval, even if they were pre-approved. |
| Risky tools | `write_file` and `shell` need approval by default; tools outside the allow-list are refused. |
| File access | Every path is resolved inside the workspace: absolute paths, `..` and symlinks that point outside are refused. |
| Code execution | `calculate` parses arithmetic with Python's `ast` instead of `eval`. `shell` runs only inside a macOS `sandbox-exec` profile with no network and writes only inside the workspace; on systems without a sandbox it is disabled (fails closed). |
| Monitoring | Every step is appended to a JSONL trace; `Trace.summary()` reports model calls, tool calls, errors, blocked calls, tokens and time. |
| Parallel work | `run_parallel` runs independent sub-agents at the same time, each with its own workspace and budget; one crashing sub-agent is reported, not fatal. |

Security decisions live in code (`guard.py`), never in the model.

## Use it

```bash
pip install -e .
ollama pull qwen3.8:27b        # any tool-capable model works
agent-harness run "Read inventory.csv and list the SKUs below 20 units" \
  --model qwen3.8:27b --workspace ./ws --ask --trace trace.jsonl
```

`--ask` asks on the terminal before every risky call; `--approve write_file` pre-approves a tool for clean sessions only.

From Python:

```python
from agent_harness.guard import Policy
from agent_harness.loop import run
from agent_harness.model import OpenAIChat
from agent_harness.tools import Workspace, default_tools

model = OpenAIChat("http://127.0.0.1:11434/v1", "qwen3.8:27b")
result = run("What is 17.5% of 2340?", model, default_tools(Workspace("./ws")), Policy())
print(result.status, result.answer, result.trace.summary())
```

## Evaluation

`python -m evals.run --model qwen3.8:27b` runs 8 ordinary tasks and 6 attacks, each in a fresh workspace with fictional files. A simulated reviewer approves only the writes a task declares as its expected output and refuses everything else.

Results with Qwen 3.8 27B running locally through Ollama on a Mac Studio (2026-11-25):

| | Result |
| --- | --- |
| Ordinary tasks (calculate, read and answer, find the lowest stock, count files, sum a CSV into a file, fix a config typo, write a summary, list SKUs to reorder) | **8 / 8 correct** |
| Attacks (injected "write pwned.txt", injected "read ../secret.txt", `/etc/hosts`, symlink to a secret, `__import__` in the calculator, injected `curl \| sh`) | **6 / 6 harmless** |
| Calls blocked by the guardrails during the run | 5 |
| Average model calls per task | 2.7 |

Read these numbers honestly:

- In four attacks (injected write, injected `../secret.txt`, calculator code, injected `curl`) the model never attempted the harmful step, so the guardrails were not needed. In the path and symlink attacks the model tried and the harness refused. The guarantee that the guardrails hold **even when the model obeys the attacker** comes from the test suite, where a scripted model performs each attack on purpose.
- Parallel sub-agents gave no speed-up here (4 small tasks: 5.9 s in sequence, 6.2 s in parallel) because Ollama answers one request at a time by default. Parallelism pays off with a server that serves concurrent requests (for example `OLLAMA_NUM_PARALLEL` or a hosted API); the harness itself runs the sub-agents concurrently, as the tests show.
- 14 tasks are a smoke test of behaviour, not a benchmark of the model.

## Tests

`pytest` runs 24 tests with a scripted fake model, so every guardrail is checked deterministically without a network or a GPU: path escapes, symlinks, injection followed by a write, approval flow, failure limits, loop detection, kill switch, budgets, the calculator, traces, parallel sub-agents, and (on macOS) that the shell sandbox blocks the network and writes outside the workspace.

```
src/agent_harness/
  model.py     OpenAI-compatible client (stdlib) and a scripted fake
  tools.py     workspace-confined tools, sandboxed shell, safe calculator
  guard.py     policy: allow-list, approvals, taint rule
  loop.py      the agent loop, budgets and stop conditions
  parallel.py  sub-agents in parallel
  trace.py     JSONL trace and summary metrics
evals/run.py   ordinary tasks and attacks against a real model
```

## Why this exists

I run a personal AI system with tools on my own machine, and these are the controls I found I needed. This repository is a clean, public version of those ideas with fictional data, so they can be read, tested and reused.

## License

MIT

"""Run independent sub-agents at the same time, each with its own workspace, tools and budget."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_harness.loop import Result


def run_parallel(
    subtasks: list[str], agent: Callable[[str, Path], Result], root: str | Path, max_workers: int = 4
) -> list[Result]:
    """agent(subtask, workspace_dir) -> Result.

    Results keep the order of `subtasks`; one failing sub-agent never stops the rest.
    """
    root = Path(root)

    def one(i_task):
        i, task = i_task
        ws = root / f"sub-{i:02d}"
        ws.mkdir(parents=True, exist_ok=True)
        try:
            return agent(task, ws)
        except Exception as exc:  # isolate: a crashing sub-agent is reported, not fatal
            return Result("stopped", "", f"sub-agent crashed: {type(exc).__name__}: {exc}")

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(one, enumerate(subtasks)))

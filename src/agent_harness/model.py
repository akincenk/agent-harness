"""Model clients: any OpenAI-compatible chat endpoint (OpenAI, Ollama, llama.cpp) and a scripted fake for tests."""

import json
import urllib.request
from dataclasses import dataclass, field


@dataclass
class Reply:
    text: str = ""
    tool_calls: list[dict] = field(default_factory=list)  # [{"id", "name", "arguments": dict}]
    tokens: int = 0


class OpenAIChat:
    """POST {base_url}/chat/completions with tool definitions. Standard library only."""

    def __init__(self, base_url: str, model: str, api_key: str = "local", timeout: float = 300):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model, self.api_key, self.timeout = model, api_key, timeout

    def __call__(self, messages: list[dict], tools: list[dict]) -> Reply:
        body = json.dumps({"model": self.model, "messages": messages, "tools": tools}).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.load(r)
        msg = data["choices"][0]["message"]
        calls = []
        for c in msg.get("tool_calls") or []:
            raw = c["function"].get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                args = {"_unparsed": raw}
            calls.append({"id": c.get("id", ""), "name": c["function"]["name"], "arguments": args})
        return Reply(msg.get("content") or "", calls, (data.get("usage") or {}).get("total_tokens", 0))


class Scripted:
    """Returns pre-written replies in order; records what it was shown. For deterministic tests and demos."""

    def __init__(self, replies: list[Reply]):
        self.replies, self.seen = list(replies), []

    def __call__(self, messages: list[dict], tools: list[dict]) -> Reply:
        self.seen.append([dict(m) for m in messages])
        return self.replies.pop(0) if self.replies else Reply("done")

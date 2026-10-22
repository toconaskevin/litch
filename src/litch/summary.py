import os
from pathlib import Path

from litch.diff import Change


def write_run_summary(
    *,
    command: str,
    config_path: str,
    result: str,
    repo: str | None = None,
    changes: list[Change] | None = None,
    error: str | None = None,
) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if not path:
        return
    lines = [
        f"## Litch `{command}`",
        "",
        f"- Config: `{config_path}`",
    ]
    if repo:
        lines.append(f"- Repository: `{repo}`")
    lines.append(f"- Result: {result}")
    lines.append("")
    if error:
        lines.extend(["### Error", "", "```", error, "```", ""])
    if changes:
        lines.extend(["### Changes", "", "```"])
        lines.extend(change.line() for change in changes)
        lines.extend(["```", ""])
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

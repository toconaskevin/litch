import argparse
import sys

from litch.config import ConfigError, load_config
from litch.engine import apply_changes, collect_values, plan
from litch.github_api import GitHub, GitHubError
from litch.github_app import installation_auth
from litch.secrets import SecretError, open_source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="litch")
    parser.add_argument("command", choices=("plan", "apply", "drift"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--definitions")
    parser.add_argument("--templates")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config, args.definitions, args.templates)
        source = open_source(config.provider)
        values = collect_values(config, source)
        token, app_id = installation_auth(source)
        changes = plan(config, GitHub(token, app_id), values)
    except (ConfigError, SecretError, GitHubError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    for change in changes:
        print(change.line())
    if args.command == "plan":
        if not changes:
            print("sin cambios")
        return 0
    if args.command == "drift":
        if not changes:
            print("sin cambios")
        return 1 if changes else 0
    if any(change.action == "missing" for change in changes):
        print("required secret is missing; nothing was written", file=sys.stderr)
        return 2
    if changes:
        try:
            apply_changes(config, GitHub(token, app_id), changes, values)
        except GitHubError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    else:
        print("sin cambios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Allow ``python -m cli`` to run the OpenCobot CLI."""

from cli.opencobot_cli import main

if __name__ == "__main__":
    raise SystemExit(main())

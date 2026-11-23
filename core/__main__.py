"""``python -m core`` starts the core daemon (same as ``python -m core.daemon``)."""

from .daemon import main

if __name__ == "__main__":
    raise SystemExit(main())

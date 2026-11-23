"""Entry point so ``python -m policy`` starts policyd."""

from .policyd import main

if __name__ == "__main__":
    raise SystemExit(main())

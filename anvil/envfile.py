"""Environment loading with a predictable precedence.

    shell environment  >  .env.local  >  .env

Real shell/CI variables always win; among files, `.env.local` (developer- or
machine-specific, gitignored) overrides the shared `.env`. Loading is
idempotent, so it's safe to call from both the CLI entry point and library
constructors. Files are searched from the current directory up to the repo root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

_loaded = False


def _find(filename: str, start: Path) -> Optional[Path]:
    for directory in [start, *start.parents]:
        candidate = directory / filename
        if candidate.is_file():
            return candidate
        if (directory / "pyproject.toml").is_file():
            break  # don't search above the project root
    return None


def load_env(start_dir: Optional[Path] = None, force: bool = False) -> None:
    """Load .env.local then .env without overriding already-set variables.

    Because neither call overrides, and .env.local is loaded first, the
    effective precedence is: existing env > .env.local > .env.
    """
    global _loaded
    if _loaded and not force:
        return

    start = Path(start_dir or Path.cwd()).resolve()
    for name in (".env.local", ".env"):
        path = _find(name, start)
        if path:
            load_dotenv(path, override=False)
    _loaded = True

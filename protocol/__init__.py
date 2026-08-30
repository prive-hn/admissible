"""Language-neutral JSON Schemas shipped with fcd."""
from pathlib import Path

_ROOT = Path(__file__).resolve().parent


def schema_path(name: str) -> Path:
    """Return one packaged schema path; reject traversal and unknown names."""
    if Path(name).name != name or not name.endswith(".json"):
        raise ValueError("schema name must be a JSON basename")
    path = _ROOT / name
    if not path.is_file():
        raise ValueError(f"unknown protocol schema {name!r}")
    return path


__all__ = ["schema_path"]

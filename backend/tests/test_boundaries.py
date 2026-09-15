"""Ядро не должно знать про базу и HTTP — иначе его нельзя гонять в CI."""
import ast
from pathlib import Path

FORBIDDEN = {"sqlalchemy", "fastapi", "httpx", "requests", "alembic"}
CORE = Path(__file__).resolve().parents[1] / "kbaudit"


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


def test_core_does_not_import_infrastructure() -> None:
    offenders = {
        str(p.relative_to(CORE)): sorted(imported_modules(p) & FORBIDDEN)
        for p in CORE.rglob("*.py")
        if imported_modules(p) & FORBIDDEN
    }
    assert offenders == {}, f"ядро тянет инфраструктуру: {offenders}"

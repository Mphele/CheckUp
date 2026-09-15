import os
from dataclasses import dataclass
from pathlib import Path


IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}
SCANNABLE_SUFFIXES = {
    ".cfg",
    ".env",
    ".ini",
    ".json",
    ".key",
    ".pem",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
DEFAULT_MAX_FILE_SIZE = 1_000_000


@dataclass(frozen=True, slots=True)
class ProjectFile:
    path: Path
    relative_path: str
    size: int


def discover_files(
    project_root: Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> list[ProjectFile]:
    root = project_root.resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)

    discovered: list[ProjectFile] = []
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current_root)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in IGNORED_DIRECTORIES
            and not (current_path / directory).is_symlink()
        )

        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or not _is_scannable(path):
                continue

            size = path.stat().st_size
            if size > max_file_size:
                continue

            discovered.append(
                ProjectFile(
                    path=path,
                    relative_path=path.relative_to(root).as_posix(),
                    size=size,
                )
            )

    return discovered


def _is_scannable(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in SCANNABLE_SUFFIXES

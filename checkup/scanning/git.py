import os
import subprocess
from pathlib import Path

from checkup.models import GitStatus


def find_git_root(project_root: Path) -> Path | None:
    result = _run_git(project_root, "rev-parse", "--show-toplevel")
    if result is None or result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def classify_git_file(git_root: Path, file_path: Path) -> GitStatus | None:
    try:
        relative_path = Path(os.path.relpath(file_path, git_root)).as_posix()
    except ValueError:
        return None

    tracked = _run_git(git_root, "ls-files", "--error-unmatch", "--", relative_path)
    if tracked is None:
        return None
    if tracked.returncode == 0:
        return GitStatus.TRACKED

    ignored = _run_git(git_root, "check-ignore", "-q", "--", relative_path)
    if ignored is None:
        return None
    if ignored.returncode == 0:
        return GitStatus.IGNORED
    return GitStatus.UNTRACKED


def _run_git(
    working_directory: Path, *arguments: str
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(working_directory), *arguments],
            capture_output=True,
            check=False,
            text=True,
            timeout=3,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None

import subprocess
from pathlib import Path

from checkup.models import GitStatus
from checkup.scanning.git import classify_git_file, find_git_root


def test_classifies_tracked_ignored_and_untracked_files(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tracked = tmp_path / "tracked.env"
    ignored = tmp_path / "ignored.env"
    untracked = tmp_path / "untracked.env"
    tracked.write_text("SECRET=tracked-value", encoding="utf-8")
    ignored.write_text("SECRET=ignored-value", encoding="utf-8")
    untracked.write_text("SECRET=untracked-value", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("ignored.env\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.env"], check=True)

    git_root = find_git_root(tmp_path)

    assert git_root == tmp_path.resolve()
    assert classify_git_file(git_root, tracked) is GitStatus.TRACKED
    assert classify_git_file(git_root, ignored) is GitStatus.IGNORED
    assert classify_git_file(git_root, untracked) is GitStatus.UNTRACKED

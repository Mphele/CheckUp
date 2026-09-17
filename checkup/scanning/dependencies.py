import re

from checkup.models import Dependency, SourceLocation


PINNED_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?"
    r"\s*==\s*([^\s;#]+)"
)


def parse_requirements(source: str, relative_path: str) -> list[Dependency]:
    dependencies: list[Dependency] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        match = PINNED_REQUIREMENT.match(line)
        if match is None:
            continue

        name, version = match.groups()
        dependencies.append(
            Dependency(
                name=_normalize_package_name(name),
                version=version,
                location=SourceLocation(path=relative_path, line=line_number),
            )
        )

    return dependencies


def is_requirements_file(relative_path: str) -> bool:
    filename = relative_path.rsplit("/", 1)[-1].lower()
    return filename.startswith("requirements") and filename.endswith(".txt")


def _normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


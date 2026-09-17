import ast

from checkup.models import Confidence, Finding, RouteInfo, Severity, SourceLocation


ROUTE_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}
SECURITY_NAME_PARTS = {
    "admin",
    "auth",
    "current_user",
    "permission",
    "require",
    "role",
    "token",
    "verify",
}
SHELL_CALLS = {
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}
DYNAMIC_CALLS = {"builtins.eval", "builtins.exec", "eval", "exec"}
FILE_CALLS = {
    "FileResponse",
    "builtins.open",
    "open",
    "os.remove",
    "os.rename",
    "os.replace",
    "os.unlink",
    "shutil.rmtree",
}


def find_fastapi_routes(source: str, relative_path: str) -> list[RouteInfo]:
    tree = ast.parse(source, filename=relative_path)
    routes: list[RouteInfo] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for decorator in node.decorator_list:
            route = _route_from_decorator(decorator)
            if route is None:
                continue

            method, path, line = route
            dependencies, security_dependencies = _dependencies(node, decorator)
            routes.append(
                RouteInfo(
                    path=path,
                    method=method,
                    handler=node.name,
                    parameters=_parameter_names(node.args),
                    dependencies=dependencies,
                    security_dependencies=security_dependencies,
                    location=SourceLocation(path=relative_path, line=line),
                )
            )

    return routes


def find_request_input_flows(source: str, relative_path: str) -> list[Finding]:
    tree = ast.parse(source, filename=relative_path)
    lines = source.splitlines()
    findings: list[Finding] = []

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(
            _route_from_decorator(decorator) is not None
            for decorator in function.decorator_list
        ):
            continue

        tainted_names = _request_parameter_names(function.args)
        _propagate_assignments(function, tainted_names)

        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            sink = _dangerous_sink(node)
            if sink is None or not _references_names(node.args[0], tainted_names):
                continue

            findings.append(
                Finding(
                    rule_id=f"fastapi.request-to-{sink}",
                    title="Request input reaches a dangerous operation",
                    description=(
                        f"A FastAPI input reaches {sink.replace('-', ' ')} in the same "
                        "route handler. A crafted request may be able to change the "
                        "operation that the server performs."
                    ),
                    category="injection",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    location=SourceLocation(path=relative_path, line=node.lineno),
                    evidence=lines[node.lineno - 1].strip()[:200],
                    remediation=(
                        _flow_remediation(sink)
                    ),
                )
            )

    return findings


def _route_from_decorator(
    decorator: ast.expr,
) -> tuple[str, str, int] | None:
    if not isinstance(decorator, ast.Call) or not decorator.args:
        return None
    if not isinstance(decorator.func, ast.Attribute):
        return None
    if decorator.func.attr not in ROUTE_METHODS:
        return None

    path_argument = decorator.args[0]
    if not isinstance(path_argument, ast.Constant) or not isinstance(
        path_argument.value, str
    ):
        return None

    return decorator.func.attr.upper(), path_argument.value, decorator.lineno


def _parameter_names(arguments: ast.arguments) -> list[str]:
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    return [parameter.arg for parameter in parameters if parameter.arg not in {"self", "cls"}]


def _dependencies(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    decorator: ast.expr,
) -> tuple[list[str], list[str]]:
    calls = [
        node
        for default in [*function.args.defaults, *function.args.kw_defaults]
        if default is not None
        for node in ast.walk(default)
        if isinstance(node, ast.Call)
    ]

    if isinstance(decorator, ast.Call):
        for keyword in decorator.keywords:
            if keyword.arg == "dependencies":
                calls.extend(
                    node
                    for node in ast.walk(keyword.value)
                    if isinstance(node, ast.Call)
                )

    dependencies: list[str] = []
    security_dependencies: list[str] = []
    for call in calls:
        wrapper = _qualified_name(call.func)
        wrapper_name = wrapper.rsplit(".", 1)[-1] if wrapper else None
        if wrapper_name not in {"Depends", "Security"} or not call.args:
            continue
        dependency = _qualified_name(call.args[0])
        if dependency is None or dependency in dependencies:
            continue

        dependencies.append(dependency)
        if wrapper_name == "Security" or _looks_security_related(dependency):
            security_dependencies.append(dependency)

    return dependencies, security_dependencies


def _qualified_name(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _looks_security_related(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in SECURITY_NAME_PARTS)


def _request_parameter_names(arguments: ast.arguments) -> set[str]:
    names: set[str] = set()
    positional = [*arguments.posonlyargs, *arguments.args]
    padded_defaults: list[ast.expr | None] = [None] * (
        len(positional) - len(arguments.defaults)
    ) + list(arguments.defaults)

    for parameter, default in zip(positional, padded_defaults, strict=True):
        if parameter.arg not in {"self", "cls"} and not _is_dependency(default):
            names.add(parameter.arg)
    for parameter, default in zip(
        arguments.kwonlyargs, arguments.kw_defaults, strict=True
    ):
        if not _is_dependency(default):
            names.add(parameter.arg)
    return names


def _is_dependency(node: ast.expr | None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _qualified_name(node.func)
    return bool(name and name.rsplit(".", 1)[-1] in {"Depends", "Security"})


def _propagate_assignments(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_names: set[str],
) -> None:
    assignments: list[tuple[ast.expr, ast.expr]] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            assignments.extend((target, node.value) for target in node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            assignments.append((node.target, node.value))

    changed = True
    while changed:
        changed = False
        for target, value in assignments:
            if not _references_names(value, tainted_names):
                continue
            for name in _assigned_names(target):
                if name not in tainted_names:
                    tainted_names.add(name)
                    changed = True


def _assigned_names(target: ast.expr) -> set[str]:
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name)
    }


def _references_names(node: ast.AST, names: set[str]) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id in names
        for child in ast.walk(node)
    )


def _dangerous_sink(call: ast.Call) -> str | None:
    function_name = _qualified_name(call.func)
    if function_name in DYNAMIC_CALLS:
        return "dynamic-code"
    if function_name in FILE_CALLS:
        return "file-path"
    if function_name == "os.system":
        return "shell"
    if function_name in SHELL_CALLS and any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in call.keywords
    ):
        return "shell"
    if isinstance(call.func, ast.Attribute) and call.func.attr in {
        "execute",
        "executemany",
    }:
        return "sql-query"
    return None


def _flow_remediation(sink: str) -> str:
    if sink == "sql-query":
        return (
            "Use parameter placeholders and pass request values separately through the "
            "database driver's parameter binding."
        )
    if sink == "file-path":
        return (
            "Resolve the requested path against a fixed application directory, then verify "
            "that the resolved path remains inside that directory before using it."
        )
    return (
        "Do not pass request-controlled values to this operation. Use a fixed set of "
        "allowed operations and validate values against it."
    )

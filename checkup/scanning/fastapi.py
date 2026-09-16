import ast

from checkup.models import RouteInfo, SourceLocation


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

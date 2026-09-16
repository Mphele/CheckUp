import ast

from checkup.models import RouteInfo, SourceLocation


ROUTE_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}


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
            routes.append(
                RouteInfo(
                    path=path,
                    method=method,
                    handler=node.name,
                    parameters=_parameter_names(node.args),
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


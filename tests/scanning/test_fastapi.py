import pytest

from checkup.models import Confidence
from checkup.scanning.fastapi import find_fastapi_routes, find_request_input_flows


def test_discovers_fastapi_route_details() -> None:
    source = '''
@router.get("/users/{user_id}")
async def get_user(user_id: int, include_profile: bool = False):
    return {"id": user_id}
'''

    routes = find_fastapi_routes(source, "app/routes.py")

    assert len(routes) == 1
    assert routes[0].method == "GET"
    assert routes[0].path == "/users/{user_id}"
    assert routes[0].handler == "get_user"
    assert routes[0].parameters == ["user_id", "include_profile"]
    assert routes[0].location.line == 2


def test_discovers_multiple_route_decorators() -> None:
    source = '''
@router.put("/profile")
@router.patch("/profile")
def update_profile():
    pass
'''

    routes = find_fastapi_routes(source, "app/routes.py")

    assert [(route.method, route.path) for route in routes] == [
        ("PUT", "/profile"),
        ("PATCH", "/profile"),
    ]


def test_ignores_unrelated_decorators() -> None:
    source = '''
@cache.result(ttl=30)
def calculate_total():
    return 42
'''

    assert find_fastapi_routes(source, "app/services.py") == []


def test_separates_security_and_non_security_dependencies() -> None:
    source = '''
@router.get("/account")
def get_account(
    database = Depends(get_database),
    user = Depends(get_current_user),
):
    pass
'''

    route = find_fastapi_routes(source, "app/routes.py")[0]

    assert route.dependencies == ["get_database", "get_current_user"]
    assert route.security_dependencies == ["get_current_user"]


def test_recognizes_route_level_security_dependency() -> None:
    source = '''
@router.delete("/users/{user_id}", dependencies=[Security(require_admin)])
def delete_user(user_id: int):
    pass
'''

    route = find_fastapi_routes(source, "app/routes.py")[0]

    assert route.dependencies == ["require_admin"]
    assert route.security_dependencies == ["require_admin"]


def test_traces_route_input_to_shell_command() -> None:
    source = '''
@router.get("/lookup")
def lookup(host: str):
    command = f"nslookup {host}"
    return subprocess.run(command, shell=True)
'''

    findings = find_request_input_flows(source, "app/routes.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "fastapi.request-to-shell"
    assert findings[0].confidence is Confidence.HIGH
    assert findings[0].location.line == 5


def test_traces_route_input_to_dynamic_execution() -> None:
    source = '''
@router.post("/calculate")
def calculate(expression: str):
    return eval(expression)
'''

    findings = find_request_input_flows(source, "app/routes.py")

    assert findings[0].rule_id == "fastapi.request-to-dynamic-code"


def test_does_not_treat_dependency_result_as_request_input() -> None:
    source = '''
@router.get("/internal")
def internal(command = Depends(trusted_command)):
    return os.system(command)
'''

    assert find_request_input_flows(source, "app/routes.py") == []


def test_ignores_safe_use_of_route_input() -> None:
    source = '''
@router.get("/users/{user_id}")
def get_user(user_id: int):
    return database.get(user_id)
'''

    assert find_request_input_flows(source, "app/routes.py") == []


def test_traces_route_input_to_sql_query() -> None:
    source = '''
@router.get("/users")
def find_user(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return database.execute(query)
'''

    findings = find_request_input_flows(source, "app/routes.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "fastapi.request-to-sql-query"
    assert "parameter placeholders" in findings[0].remediation


@pytest.mark.parametrize(
    "operation",
    [
        "open(filename)",
        "FileResponse(filename)",
        "os.remove(filename)",
    ],
)
def test_traces_route_input_to_file_operation(operation: str) -> None:
    source = f'''
@router.get("/files")
def get_file(filename: str):
    return {operation}
'''

    findings = find_request_input_flows(source, "app/routes.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "fastapi.request-to-file-path"
    assert "fixed application directory" in findings[0].remediation


def test_ignores_fixed_file_path() -> None:
    source = '''
@router.get("/terms")
def terms():
    return FileResponse("static/terms.pdf")
'''

    assert find_request_input_flows(source, "app/routes.py") == []

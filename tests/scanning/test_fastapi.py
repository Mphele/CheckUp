from checkup.scanning.fastapi import find_fastapi_routes


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

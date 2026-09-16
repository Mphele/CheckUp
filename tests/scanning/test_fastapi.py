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

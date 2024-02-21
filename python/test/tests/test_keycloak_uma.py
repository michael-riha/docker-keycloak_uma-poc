from python.fastAPI.app.oauth_client import OAuthClient


# content of test_sample.py
def func(x):
    return x + 1


def test_it():
    print('here')  # <- add breakpoint here


def test_answer():
    result = func(4)
    print(f"let's test the answer: {result}")
    assert result == 5


def test_keycloak_uma():
    client = OAuthClient()

    uma = client.uma
    # https://github.com/marcospereirampj/python-keycloak/blob/master/tests/test_keycloak_uma.py
    resource_sets = uma.resource_set_list()
    resource_set_list = list(resource_sets)

    # https://github.com/marcospereirampj/python-keycloak/blob/bc810d17cbd66bc6315409508aec386c6b8180b1/tests/test_keycloak_uma.py#L92
    resource_to_create = {
        "name": "mytest",
        "scopes": ["test:read", "test:write"],
        "type": "urn:test",
    }
    created_resource = uma.resource_set_create(resource_to_create)
    get_created_resource = uma.resource_set_read(created_resource["_id"])
    print("something")

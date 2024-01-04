# content of test_sample.py
def func(x):
    return x + 1

def test_it():
    print('here') # <- add breakpoint here

def test_answer():
    result= func(4)
    print(f"let's test the answer: {result}")
    assert result == 5

from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakOpenIDConnection, KeycloakUMA
import os
def test_keycloak_uma():
     # https://github.com/marcospereirampj/python-keycloak/blob/bc810d17cbd66bc6315409508aec386c6b8180b1/tests/conftest.py#L509
    connection = KeycloakOpenIDConnection(
        server_url=os.environ.get("KEYCLOAK_URL"),
        realm_name=os.environ.get("KEYCLOAK_REALM"),
        client_id=os.environ.get("KEYCLOAK_CLIENT_ID"),
        client_secret_key=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
        timeout=20,
    )

    # https://github.com/marcospereirampj/python-keycloak/blob/bc810d17cbd66bc6315409508aec386c6b8180b1/tests/conftest.py#L530C11-L530C45
    uma = KeycloakUMA(connection=connection)
    # https://github.com/marcospereirampj/python-keycloak/blob/master/tests/test_keycloak_uma.py
    resource_sets = uma.resource_set_list()
    resource_set_list = list(resource_sets)
    print("something")
    # https://github.com/marcospereirampj/python-keycloak/blob/bc810d17cbd66bc6315409508aec386c6b8180b1/tests/test_keycloak_uma.py#L92
    resource_to_create = {
        "name": "mytest",
        "scopes": ["test:read", "test:write"],
        "type": "urn:test",
    }
    created_resource = uma.resource_set_create(resource_to_create)
    get_created_resource = uma.resource_set_read(created_resource["_id"])
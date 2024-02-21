import os
from typing import Annotated

import requests
import uvicorn
from authlib.jose.errors import *
from fastapi import Depends, status
from fastapi import FastAPI, Request, HTTPException
# https://fastapi.tiangolo.com/advanced/custom-response/#html-response
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
# https://fastapi.tiangolo.com/es/advanced/custom-response/#redirectresponse
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from keycloak.exceptions import KeycloakPostError

# HACK
# TODO put the helpers into a dedicated folder !WARNING! this needs to be mounted in python as well!!
# import sys
# # Get the absolute path of the parent folder
# parent_folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# # Add the parent folder to the Python path
# sys.path.append(parent_folder_path)
from helper.oidc import check_bearer
from helper.oidc import verify_jwt
from keycloack_client import KeycloakClient
from oauth_client import OAuthClient
from schemas import AuthData

app = FastAPI()

# TODO: just for feasibility -> SHARED STATE https://www.vidavolta.io/sharing-memory/
state = {}  # HACK store the bearer_token for now!


@app.get("/")
def redirect_to_home(request: Request):
    # return {"raw_url": request.url._url}
    return RedirectResponse(request.url._url + "home")


@app.get("/home")
def read_root():
    print("something")
    return {"Hello": "World"}


@app.get('/resource')
def authorized_resource(
    token: Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl='token'))],
) -> dict:
    check_permissions(
        token=token, permissions='myresource#read',
    )

    return {'foo': 'bar'}


@app.get("/private")
def get_private(request: Request):
    return check_bearer(request)


@app.get("/callback")
def get_callback(request: Request):
    print("something")
    client = OAuthClient()
    resp = requests.get(url=client.oidcDiscoveryUrl)
    token_url = resp.json()["token_endpoint"]
    redirect_uri = request.url.scheme + "://" + request.url.netloc + "/callback"
    token_resp = client.oidc_client.fetch_token(url=token_url, authorization_response=request.url._url,
                                                redirect_uri=redirect_uri,
                                                authorization_code='authorization_code')
    # https://github.com/lepture/authlib/blob/c8f154ff35459f79cc04f4c214601d25d716ddd4/docs/specs/rfc7636.rst#L83
    state['bearer_token'] = token_resp['access_token']
    return RedirectResponse('/me')


@app.get("/me", response_class=HTMLResponse)
def get_me(request: Request):
    client = OAuthClient()
    resp = requests.get(url=client.oidcDiscoveryUrl)
    userinfo_endpoint = resp.json()["userinfo_endpoint"]
    # HACK for browser redirect outside the container environment we need to replace `host.docker.internal` with `localhost`
    userinfo_endpoint = userinfo_endpoint.replace(os.environ.get("KEYCLOAK_URL"),
                                                  os.environ.get("KEYCLOAK_BROWSER_URL"))
    javascript_code = '''
        let endpointUrl = '{{url}}';
        const bearerToken = '{{token}}';

        function request(url) {
            fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${bearerToken}`
                }
                })
                .then(response => {
                    if (!response.ok) {
                    throw new Error('Network response was not ok');
                    }
                    return response.json(); // Parse the JSON data received
                })
                .then(data => {
                    // Work with the 'data' received from the API
                    console.log('Data received:', data);
                    document.querySelector("h1").textContent= "Hello "+data.name+"("+data.email+")"
                })
                .catch(error => {
                    console.error('There was a problem with the fetch operation:', error);
                });
        }
        request(endpointUrl )

    '''
    # Replace placeholders with actual values using str.replace()
    javascript_code = javascript_code.replace('{{url}}', userinfo_endpoint).replace('{{token}}', state['bearer_token'])
    return """
        <html>
            <head>
                <title>Some UserInfo in here</title>
                <script>
                   {javascript_code}
                </script>
            </head>
            <body>
                <h1></h1>
                <a href='/verify'><h2>Verify JWT</h2></a>
            </body>
        </html>
    """.format(javascript_code=javascript_code)


@app.get("/verify")
def get_callback(request: Request):
    print("something")
    try:
        # token = check_bearer(request)
        verify_jwt(state['bearer_token'])
        # verify_jwt(token)
        return {"Hello": "/verify"}
    # TODO: get a more detailed exception
    except ExpiredTokenError:
        # Token has expired
        raise HTTPException(status_code=401, detail="Invalid JWT: Token has expired")
    except MissingClaimError as e:
        # Missing required claims
        raise HTTPException(status_code=401, detail=f"Invalid JWT: Missing claim - {e}")
    except InvalidClaimError as e:
        # Invalid claims
        raise HTTPException(status_code=401, detail=f"Invalid JWT: {e}")
    except InvalidTokenError:
        # Invalid token
        raise HTTPException(status_code=401, detail="Invalid JWT: Token is not valid")


@app.get("/uma")
def get_uma():
    client = OAuthClient()
    # https://github.com/marcospereirampj/python-keycloak/blob/master/tests/test_keycloak_uma.py
    resource_sets = client.uma.resource_set_list()
    resource_set_list = list(resource_sets)
    return JSONResponse(content={"data": resource_set_list})


# TODO: not working, yet!
@app.post("/uma")
def set_uma():
    client = OAuthClient()
    # https://github.com/marcospereirampj/python-keycloak/blob/bc810d17cbd66bc6315409508aec386c6b8180b1/tests/test_keycloak_uma.py#L92
    resource_to_create = {
        "name": "mytest",
        "scopes": ["test:read", "test:write"],
        "type": "urn:test",
    }
    created_resource = client.uma.resource_set_create(resource_to_create)
    get_created_resource = client.uma.resource_set_read(created_resource["_id"])


@app.post('/auth')
def authorize(auth_data: AuthData):
    keycloak_client = KeycloakClient()
    token = keycloak_client.oidc_client.token(**auth_data.model_dump())
    return token


# KeycloakClient
@app.get('/uma_resources_list')
def get_uma_resource_set_list():
    keycloak_client = KeycloakClient()
    return keycloak_client.uma.resource_set_list()


def check_permissions(token: str, permissions: str) -> None:
    keycloak_client = KeycloakClient()
    try:
        keycloak_client.oidc_client.uma_permissions(
            token,
            permissions=permissions,
        )
    except KeycloakPostError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


if __name__ == '__main__':
    # For debug purposes
    uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=True)

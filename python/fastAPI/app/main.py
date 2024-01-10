from fastapi import FastAPI, Request, HTTPException
import os

app = FastAPI()

# https://fastapi.tiangolo.com/es/advanced/custom-response/#redirectresponse
from fastapi.responses import RedirectResponse
@app.get("/")
def redirect_to_home(request: Request):
    #return {"raw_url": request.url._url}
    return RedirectResponse(request.url._url+"home")

@app.get("/home")
def read_root():
    print("something")
    return {"Hello": "World"}


# ----------- BROWSER FLOW AUTH -----------
issuer = os.environ.get("KEYCLOAK_URL")+"realms/"+os.environ.get("KEYCLOAK_REALM")
clientId = os.environ.get("KEYCLOAK_CLIENT_ID")
clientSecret = os.environ.get("KEYCLOAK_CLIENT_SECRET")
oidcDiscoveryUrl = f'{issuer}/.well-known/openid-configuration'
# from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.requests_client import OAuth2Session
scope = 'openid email profile'
# scope = 'email'
#client = OAuth2Session(clientId, clientSecret, scope=scope, redirect_uri=redirect_uri)
client = OAuth2Session(clientId, clientSecret, scope=scope)
#TODO: just for feasibility -> SHARED STATE https://www.vidavolta.io/sharing-memory/
state = {} #HACK store the bearer_token for now!


import requests
import secrets
from urllib.parse import urlencode, quote
from helper.oidc import check_bearer, get_discovery_response
@app.get("/private")
def get_private(request: Request):
    try:
        # Accessing the Authorization header
        authorization_header = request.headers.get("Authorization")
        if authorization_header is None:
            raise HTTPException(status_code=401, detail="Authorization header is missing")
        # Check if the Authorization header starts with 'Bearer'
        if not authorization_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        # Extract the token after 'Bearer '
        bearer_token = authorization_header.split(" ")[1]
    except HTTPException as e:
        # Catch HTTPException and perform a redirect
        if e.status_code == 401:
            resp = requests.get(url=oidcDiscoveryUrl)
            auth_url = resp.json()["authorization_endpoint"]
            #HACK for browser redirect outside the container environment we need to replace `host.docker.internal` with `localhost`
            auth_url = auth_url.replace(os.environ.get("KEYCLOAK_URL"), os.environ.get("KEYCLOAK_BROWSER_URL"))
            response_type = 'code'
            client_id = 'myclient'
            redirect_uri = request.url.scheme+"://"+request.url.netloc+"/callback"
            # Encoding the redirect_uri
            # redirect_uri= quote(redirect_uri, safe='')
            state = 'xyz123'
            # Generate a random string for nonce
            nonce_value = secrets.token_urlsafe(16)  # Adjust the length as needed (16 bytes here)
            login_url= f"{auth_url}?response_type={response_type}&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}&nonce={nonce_value}"
            # INFO: redirect_uri used from the client settings ->  http://localhost:8090/admin/master/console/#/myrealm/clients/daabac99-9ee9-412c-bcac-1c635d6657f5/settings
            uri, state = client.create_authorization_url(auth_url, redirect_uri=redirect_uri)
            return RedirectResponse(uri)
        else:
                # Handle other HTTPException cases here
                raise e  # Re-raise the exception if not handled
    return {"User-Agent": user_agent, "Content-Type": content_type}

@app.get("/callback")
def get_callback(request: Request):
    print("something")
    resp= requests.get(url=oidcDiscoveryUrl)
    token_url= resp.json()["token_endpoint"]
    redirect_uri = request.url.scheme+"://"+request.url.netloc+"/callback"
    token_resp = client.fetch_token(url=token_url, authorization_response=request.url._url, redirect_uri= redirect_uri, authorization_code='authorization_code')
    # https://github.com/lepture/authlib/blob/c8f154ff35459f79cc04f4c214601d25d716ddd4/docs/specs/rfc7636.rst#L83
    state['bearer_token'] = token_resp['access_token']
    return RedirectResponse('/me')

# https://fastapi.tiangolo.com/advanced/custom-response/#html-response
from fastapi.responses import HTMLResponse
@app.get("/me", response_class=HTMLResponse)
def get_me(request: Request):
    resp= requests.get(url=oidcDiscoveryUrl)
    userinfo_endpoint = resp.json()["userinfo_endpoint"]
    #HACK for browser redirect outside the container environment we need to replace `host.docker.internal` with `localhost`
    userinfo_endpoint = userinfo_endpoint.replace(os.environ.get("KEYCLOAK_URL"), os.environ.get("KEYCLOAK_BROWSER_URL"))
    javascript_code = '''
        const endpointUrl = '{{url}}';
        const bearerToken = '{{token}}';

        fetch(endpointUrl, {
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
    '''
    # Replace placeholders with actual values using str.replace()
    javascript_code = javascript_code.replace('{{url}}',  userinfo_endpoint).replace('{{token}}', state['bearer_token'])
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
            </body>
        </html>
    """.format(javascript_code=javascript_code)

# ----------- UMA -----------
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakOpenIDConnection, KeycloakUMA
@app.get("/uma")
def get_uma():
    # do we have all env vars ready?
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
    return {"Hello": "World"}

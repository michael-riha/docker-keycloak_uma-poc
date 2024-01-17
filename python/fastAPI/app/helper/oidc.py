import os

issuer = os.environ.get("KEYCLOAK_URL")+"realms/"+os.environ.get("KEYCLOAK_REALM")
clientId = os.environ.get("KEYCLOAK_CLIENT_ID")
clientSecret = os.environ.get("KEYCLOAK_CLIENT_SECRET")
oidcDiscoveryUrl = f'{issuer}/.well-known/openid-configuration'

scope = 'openid email profile'

import requests
import secrets
from urllib.parse import urlencode, quote

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
def check_bearer (request: Request):
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
        return bearer_token
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
            return RedirectResponse(login_url)
        else:
                # Handle other HTTPException cases here
                raise e  # Re-raise the exception if not handled

def get_discovery_response():
     return requests.get(url=oidcDiscoveryUrl)

def get_discovery_response_dict():
     return get_discovery_response().json()

def encode_url(url):
    return quote(url, safe='')

def redirect_uri_relative(request:Request, path:str):
    return request.url.scheme+"://"+request.url.netloc+path

def clean_browser_url(url:str):
    #HACK for browser redirect outside the container environment we need to replace `host.docker.internal` with `localhost`
    return url.replace(os.environ.get("KEYCLOAK_URL"), os.environ.get("KEYCLOAK_BROWSER_URL"))

from authlib.jose import jwt
from authlib.jose.errors import *
def get_public_keys():
    # Fetching OIDC discovery information
    discovery_info= get_discovery_response_dict()
     # Fetching JWKS URI from discovery information
    jwks_uri = discovery_info['jwks_uri']
    # Fetching JWKS (JSON Web Key Set) from JWKS URI
    jwks_response = requests.get(jwks_uri)
    jwks = jwks_response.json()
    # Fetching the JWT certificate from JWKS https://docs.authlib.org/en/latest/jose/jwt.html#use-dynamic-keys
    return jwks
# https://www.scottbrady91.com/python/authlib-python-jwt
def verify_jwt(token:str):
    # Fetching the JWT certificate from JWKS
    jwks = get_public_keys()
    # Verify the JWT token using the retrieved certificates
    decoded_jwt = jwt.decode(token, key=jwks)
    # If decoding is successful, `decoded_jwt` will contain the decoded token information

    # Accessing JWT body attributes (claims) https://docs.authlib.org/en/latest/specs/rfc7519.html#authlib.jose.JWTClaims
    if decoded_jwt:
        # Example of accessing specific claims/attributes
        sub = decoded_jwt.get('sub')  # Example: subject claim
        iss = decoded_jwt.get('iss')  # Example: issuer claim
        exp = decoded_jwt.get('exp')  # Example: expiration time claim

        # Print or use the retrieved claims/attributes as needed
        print("Subject:", sub)
        print("Issuer:", iss)
        print("Expiration Time:", exp)
    try:
        decoded_jwt.validate()
        return decoded_jwt
    except ExpiredTokenError as e:
        # Token has expired
        raise e
    except MissingClaimError as e:
        # Missing required claims
        raise e
    except InvalidClaimError as e:
        # Invalid claims
        raise e
    except InvalidTokenError:
        # Invalid token
        raise e

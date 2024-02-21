from authlib.integrations.requests_client import OAuth2Session
from keycloak import KeycloakOpenIDConnection, KeycloakUMA

from config import settings


class OAuthClient:
    _instance = None
    client_id = settings.KEYCLOAK_CLIENT_ID
    client_secret = settings.KEYCLOAK_CLIENT_SECRET
    server_url = settings.KEYCLOAK_URL
    realm_name = settings.KEYCLOAK_REALM
    timeout = settings.KEYCLOAK_TIMEOUT
    scope = 'openid'
    issuer = server_url + "realms/" + realm_name
    oidcDiscoveryUrl = f'{issuer}/.well-known/openid-configuration'

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(OAuthClient, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.oidc_client = OAuth2Session(client_id=self.client_id, client_secret=self.client_secret, scope=self.scope)
        self.uma = KeycloakUMA(
            KeycloakOpenIDConnection(client_id=self.client_id, client_secret_key=self.client_secret,
                                     server_url=self.server_url, realm_name=self.realm_name, timeout=self.timeout)
        )

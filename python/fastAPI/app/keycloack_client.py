from keycloak import KeycloakOpenIDConnection, KeycloakUMA, KeycloakOpenID

from config import settings


class KeycloakClient:
    _instance = None
    client_credentials = {
        'server_url': settings.KEYCLOAK_URL,
        'realm_name': settings.KEYCLOAK_REALM,
        'client_id': settings.KEYCLOAK_CLIENT_ID,
        'client_secret_key': settings.KEYCLOAK_CLIENT_SECRET,
        'timeout': settings.KEYCLOAK_TIMEOUT,
    }

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(KeycloakClient, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.oidc_client = KeycloakOpenID(**self.client_credentials)
        self.uma = KeycloakUMA(
            KeycloakOpenIDConnection(**self.client_credentials)
        )

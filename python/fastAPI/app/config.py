from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    KEYCLOAK_URL: str
    KEYCLOAK_REALM: str
    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str
    KEYCLOAK_TIMEOUT: int = 20  # Default value of 20 if not provided

    class Config:
        env_file = ".env"  # Optional: Load environment variables from a file


# Create an instance of the settings model
settings = Settings()

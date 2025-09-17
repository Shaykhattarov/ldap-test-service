import os

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    # Auth LDAP-protocol
    ldap_enable: bool = Field(
        default=True, description="Enable LDAP"
    )
    ldap_server_host: str = Field(
        default="ip-address", description="LDAP-server IP-address"
    )
    ldap_server_port: int = Field(
        default=8000, description="LDAP-server port"
    )
    ldap_app_dn: str = Field(
        default="app dn", description="Search app domain name filter"
    )
    ldap_app_password: str = Field(
        default="password", description="Mock LDAP password for authentication"
    )
    ldap_user_search_base_dn: str = Field(
        default="user search dn", description="User search base domain name filter"
    )
    ldap_service_search_base_dn: str = Field(
        default="user search dn", description="Service search base domain name filter"
    )
    ldap_user_search_filter: str = Field(
        default="user search filter", description="Search user domain name filter"
    )
    ldap_service_search_filter: str = Field(
        default="user search filter", description="Search service domain name filter"
    )
    ldap_use_tls: bool = Field(
        default=False, description="Parameter for enable/disable secure LDAP"
    )
    ldap_ca_cert_file: str = Field(
        default="/certs/ldaps.crt", description="Path to LDAPS certificate"
    )

    # Logs
    log_level: str = Field(default="DEBUG", description="Logging level")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string",
    )

    # Templates and static
    basedir: str = os.path.dirname(os.path.abspath(__file__))

    class Config:
        extra="allowed"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False



settings = Settings()

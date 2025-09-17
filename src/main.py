from config import settings
from services.client_ldap import LDAPConfig, LDAPClient


def main():
    
    config = LDAPConfig(
        host=settings.ldap_server_host,
        port=settings.ldap_server_port,
        bind_db=settings.ldap_app_dn,
        bind_password=settings.ldap_app_password,
        use_ssl=settings.ldap_use_tls,
        ca_cert_file=settings.ldap_ca_cert_file,
    )

    ldap_client = LDAPClient(config)

    if ldap_client.connect():
        try:
            ldap_users = ldap_client.get_all_users()
            print("Список пользователей: \n", ldap_users)
        finally:
            ldap_client.disconnect()


if __name__ == "__main__":
    main()

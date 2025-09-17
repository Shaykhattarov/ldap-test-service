import ssl

from typing import ( 
    Any,
    List, 
    Dict,
    Tuple,
    Optional,
)
from dataclasses import dataclass

from ldap3 import (
    Tls, 
    Server,
    Connection, 
    ALL,
    SUBTREE,
)
from ldap3.core.exceptions import (
    LDAPException, 
    LDAPBindError
)

from config import settings
from services.logger import setup_logger


logger = setup_logger("CLIENT_LDAP")


@dataclass
class LDAPConfig:
    host: str
    port: int = 389
    bind_dn: str = None
    bind_password: str = None
    base_dn: str = None
    use_ssl: bool = False
    ca_cert_file: Optional[str] = None
    validate_ssl: bool = True
    timeout: int = 30
    authentication: str = "SIMPLE"


class LDAPClient:
    """ Класс для работы с LDAP-сервером """

    def __init__(self, config: LDAPConfig):
        """ Инициализация LDAP-клиента """
        self.config = config
        self.connection: Optional[Connection] = None
        self.is_connected = False

    def connect(self) -> bool:
        """ Установка подключения к LDAP-серверу """
        try:
            # Формирование URL сервера
            scheme = "ldaps" if self.config.use_ssl else "ldap"
            server_url = f"{scheme}://{self.config.host}:{self.config.port}"

            # Настройка TLS
            tls_config: Optional[Tls] = None
            if self.config.use_ssl:
                tls_config = Tls(
                    validate=ssl.CERT_REQUIRED if self.config.validate_ssl else ssl.CERT_NONE,
                    ca_certs_file=self.config.ca_cert_file,
                    version=ssl.PROTOCOL_TLS_CLIENT
                )

            # Создание сервера
            server = Server(
                server_url,
                use_ssl=self.config.use_ssl,
                tls=tls_config,
                get_info=ALL,
                connect_timeout=self.config.timeout
            )

            # Создание подключения
            self.connection = Connection(
                server=server,
                user=self.config.bind_dn,
                password=self.config.bind_password,
                auto_bind=True,
                authentication=self.config.authentication,
                receive_timeout=self.config.timeout
            )

            self.is_connected = True
            logger.info(f"Успешное подключение к {server_url}")
            logger.info(f"Информация о сервере: {server.info}")

            return True
        
        except LDAPBindError as err:
            logger.error(f"Ошибка аутентификации: {err}")
            return False
        except LDAPException as err:
            logger.error(f"Ошибка подключения к LDAP: {err}")
            return False
        except Exception as err:
            logger.error(f"Неожиданная ошибка: {err}")
            return False
        
    def disconnect(self) -> None:
        """Закрытие подключения к LDAP серверу"""
        if self.connection and self.is_connected:
            try:
                self.connection.unbind()
                self.is_connected = False
                logger.info("LDAP подключение закрыто")
            except Exception as err:
                logger.error(f"Ошибка при закрытии подключения: {err}")

    def search(
        self,
        search_filter: str,
        attributes: List[str] = None,
        search_base: str = None,
        scope: str = SUBTREE,
        size_limit: int = 0
    ) -> List[Dict[str, Any]]:
        """ Поиск записей по LDAP """
        if not self.is_connected:
            raise ConnectionError("Нет активного подключения к LDAP")
        
        search_base = search_base or self.config.base_dn
        attributes = attributes or ['*']

        try:
            self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes,
                size_limit=size_limit
            )

            results = []
            for entry in self.connection.entries:
                result = {}
                for attr in attributes:
                    if attr in entry:
                        result[attr] = str(entry[attr]) if entry[attr] else None
                results.append(result)
            
            logger.info(f"Найдено {len(results)} записей")
            return results 
        
        except LDAPException as err:
            logger.error(f"Ошибка поиска: {err}")
            raise

    def get_all_users(self) -> Tuple[Dict[str, Any]]: 
        """ Получение всех УЗ LDAP """
        # BaseDn и Filter для поиска по списку УЗ пользователей
        user_search_base: str = settings.ldap_user_search_base_dn
        user_search_filter: str = settings.ldap_user_search_filter

        # BaseDn и Filter для поиска по списку сервисных УЗ
        service_search_base: str = settings.ldap_service_search_base_dn
        service_search_filter: str = settings.ldap_service_search_filter

        attributes = ["cn", "mail"]

        users: List[Dict[str, Any]] = self.search(
            search_base=user_search_base,
            search_filter=user_search_filter,
            attributes=attributes
        )

        services: List[Dict[str, Any]] = self.search(
            search_base=service_search_base,
            search_filter=service_search_filter,
            attributes=attributes
        )

        # Список всех УЗ LDAP
        results: Tuple[Dict[str, Any]] = (*users, *services)

        return results

# class LDAPAuthentication:
#     """Класс реализующий логику аутентификации пользователя по протоколу LDAP"""

#     def __create_connection_app(self):
#         """Функция для совершения первого bind к LDAP-сервису"""
#         tls_config: Optional[Tls] = None
#         if settings.ldap_use_tls:
#             tls_config = Tls(
#                 validate=ssl.CERT_REQUIRED,
#                 ca_certs_file=settings.ldap_ca_cert_file,
#                 version=ssl.PROTOCOL_TLS_CLIENT
#             )
        
#         self.server = Server(
#             host=settings.ldap_server_host,
#             port=int(settings.ldap_server_port),
#             get_info=NONE,
#             use_ssl=settings.ldap_use_tls,
#             tls=tls_config
#         )

#         self.connection_app = Connection(
#             server=self.server,
#             user=settings.ldap_app_dn,
#             password=settings.ldap_app_password,
#             auto_bind="NONE",
#             authentication="SIMPLE" if settings.ldap_app_dn else "ANONYMOUS",
#         )

#         if not self.connection_app.bind():
#             raise Exception("Application account bind failed")

#     def __search_all_users(self) -> List[dict]:
#         """Функция для получения полного списка пользователей группы"""
#         search_attributes = {
#             settings.ldap_attribute_for_mail,
#             "cn",
#         }

#         # Получение всех пользовательских учеток
#         user_search_success = self.connection_app.search(
#             search_base=settings.ldap_user_search_base_dn,
#             search_filter=f"({settings.ldap_user_search_filter})",
#             attributes=search_attributes,
#         )

#         user_entries = self.connection_app.entries

#         if not user_search_success or not self.connection_app.entries:
#             raise Exception("User not found in the LDAP server")

#         # Получение всех сервисных учеток
#         service_search_success = self.connection_app.search(
#             search_base=settings.ldap_service_search_base_dn,
#             search_filter=f"({settings.ldap_service_search_filter})",
#             attributes=search_attributes,
#         )

#         service_entries = self.connection_app.entries

#         if not service_search_success or not self.connection_app.entries:
#             raise Exception("Service not found in the LDAP server")

#         entries: List = []
#         entries.extend(
#             user_entries
#         )  # добавляем в entries результаты по получению пользоват. учеток
#         entries.extend(
#             service_entries
#         )  # добавляем в entries рез-ты по получению сервис. учеток
#         output: List = []

#         for entry in entries:
#             # Проверяем есть ли аттрибут, так как не все СУЗ имеют 'mail'
#             if entry[settings.ldap_attribute_for_mail].value is None:
#                 continue
#             mail = entry[settings.ldap_attribute_for_mail].value
#             mail = mail.lower()
#             output.append(
#                 {"fullname": str(entry["cn"]), "mail": mail, "dn": entry.entry_dn}
#             )

#         return output

#     def get_all_ldap_users(self) -> List[dict]:
#         """Функция для получения списка всех пользователей сети в компании"""
#         try:
#             self.__create_connection_app()
#             users = self.__search_all_users()
#         except Exception as err:
#             logging.exception(err)
#             return []
#         else:
#             logging.info("Getting all LDAP-users success")
#             return users

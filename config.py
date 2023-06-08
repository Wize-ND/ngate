from typing import Literal, Optional, Any
from cx_Oracle import makedsn
from pydantic import BaseModel, validator


class Dbconfig(BaseModel):
    host: Optional[str]
    port: Optional[int]
    sid: Optional[str]
    service_name: Optional[str]
    tns_name: Optional[str]
    sql_timeout: int = 600  # 10 min
    dsn: Any

    @validator('dsn', always=True)
    def get_oracle_dsn(cls, v, values):
        i = [v for v in values if v in ['sid', 'service_name', 'tns_name'] and values[v]]
        if len(i) != 1:
            raise ValueError(f'either one of sid/service_name/tns_name must be in config for oracle. {len(i)} given')

        if values['tns_name']:
            return values['tns_name']

        if not values['host'] or not values['port']:
            raise ValueError('host/port key is missing for oracle in config')

        if values['service_name']:
            return makedsn(values['host'],
                           values['port'],
                           service_name=values['service_name'])

        return makedsn(values['host'],
                       values['port'],
                       sid=values['sid'])


class Ldapconfig(BaseModel):
    host: str
    bind_dn: str
    password: str
    base_user_dn: str
    filter_users: str
    key: str
    ldap_auth_only: Optional[bool]


class Config(BaseModel):
    logging_level: str = 'INFO'
    port: int = 1976
    client_timeout: int = 600  # 10 min
    oracle: Dbconfig
    ldap: Optional[Ldapconfig]
    ORAGATE_REDIRECT: Optional[str]

import asyncio
import functools
import hashlib
import re
import uuid
import cx_Oracle
import ldap


async def doauth(login: str, password: str, server: dict):
    """
    Perform login attempt
    :param login: login
    :param password: password
    :param server: server dict
    :return: False/True, error(str)/cregentials(tuple)
    """
    loop = asyncio.get_event_loop()
    if server['type'] == 'LOCAL':
        return await loop.run_in_executor(None, functools.partial(auth_oracle, login, password, server))
    if server['type'] == 'NGATE':
        success, server_answer = await async_auth_ngate(login, password, server)
    elif server['type'] == 'LDAP':
        success, server_answer = await loop.run_in_executor(None, functools.partial(auth_ldap, login, password, server))
    else:
        return False, f'Unknown auth server type: {server["type"]}'
    if success:
        return True, gen_oracle_credentials(server_answer, server['key'])
    return False, server_answer


def gen_oracle_credentials(ldap_guid: str, key: str) -> tuple:
    def baseN(num, b, numerals='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_'):
        return ((num == 0) and numerals[0]) or (baseN(num // b, b, numerals).lstrip(numerals[0]) + numerals[num % b])

    return f'L0_{baseN(int(ldap_guid, 16), 37)}', f'P0_{baseN(int(hashlib.md5((ldap_guid + key).encode()).hexdigest(), 16), 37)}'


async def async_auth_ngate(login: str, password: str, server: dict, **kwargs):
    app_session_id = 'n/a'
    if 'app_session_id' in kwargs:
        app_session_id = kwargs['app_session_id']
    try:
        reader, writer = await asyncio.open_connection(server["host"], server["port"])
        conn_str = f'LOGIN user="{login}" password="{password}" ' \
                   'app="eqm-web-app" version="1.0.0.0" required_filters="" desired_filters="" packet_size="10" local_ip="" ' \
                   f'app_session_id="{app_session_id}"\r\n'
        writer.write(conn_str.encode())
        await writer.drain()
        data = await reader.read(100)
        writer.close()
        await writer.wait_closed()
        hit = re.search(r'^\+OK.*ldap_guid\=\"(?P<ldap_guid>.*)\"', data.decode())
        if hit and 'ldap_guid' in hit.groupdict():
            return True, hit.groupdict()['ldap_guid']
        else:
            return False, data.decode()
    except Exception as e:
        return False, str(e)


def auth_ldap(login: str, password: str, server: dict):
    ldap_filter = server['filter_users'].format(login)
    connect = ldap.initialize(f'ldap://{server["host"]}')
    connect.set_option(ldap.OPT_REFERRALS, 0)
    connect.simple_bind_s(server['bind_dn'], server['password'])
    hit = connect.search_s(server['base_user_dn'], ldap.SCOPE_SUBTREE, ldap_filter, ['ObjectGUID'])
    if hit:
        user_dn = hit[0][0]
        objectGUID = uuid.UUID(bytes_le=hit[0][1]['objectGUID'][0]).hex.upper()
    else:
        return False, f'person ({login}) not found'
    try:
        connect.simple_bind_s(user_dn, password)
        connect.unbind()
    except Exception as e:
        return False, str(e)
    return True, objectGUID


def auth_oracle(login, password, server):
    try:
        connection = cx_Oracle.Connection(login, password, server['dsn'], encoding='UTF-8')
        cursor = connection.cursor()
        cursor.execute("select * from dual")
        cursor.close()
        connection.close()
    except Exception as e:
        return False, str(e)
    return True, (login, password)

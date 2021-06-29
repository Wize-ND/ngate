import asyncio
import functools
import hashlib
import logging
import os
import re
import uuid
import zlib

import cx_Oracle
import ldap

from models.eqm_user_session import EqmUserSession
from db import default_output


async def doauth(login_str: str, session: EqmUserSession):
    """
    Perform login attempt
    :param login_str: login string
    :param session: EqmUserSession
    :return: False/True, error(str)/session_parameters(dict)
    """
    loop = asyncio.get_event_loop()
    log = logging.getLogger('auth')
    message = ''
    error = None

    login_dict = {i.group('key'): i.group('value') for i in
                  re.finditer(r'(?P<key>\w+)="(?P<value>.*?)"\s', login_str, re.MULTILINE)}
    session.update(**login_dict)
    if 'ldap' in session.oragate_cfg:
        ldap_success, server_answer = await loop.run_in_executor(None,
                                                                 functools.partial(auth_ldap, session.user, session.password, session.oragate_cfg['ldap']))
        if session.oragate_cfg['ldap_auth_only']:
            if ldap_success:
                message = f'redirect="{session.oragate_cfg["ORAGATE_REDIRECT"]}" ldap_guid="{server_answer}"'
                log.info(f'Successful ldap-auth-only : {session} ldap_guid = {server_answer}')
            else:
                error = server_answer
                log.info(f'Access denied : {session}; error message = "{server_answer}"')
        else:
            if ldap_success:
                log.info(f'Successful ldap login : {session}')
                session.ora_user, session.password = gen_oracle_credentials(server_answer, session.oragate_cfg['ldap']['key'])
                ora_success, server_answer = await auth_oracle(session.ora_user, session.password, session)
                if ora_success:
                    session.db_conn = server_answer
                else:
                    error = server_answer
            else:
                error = server_answer
                log.info(f'Access denied : {session}; error message = "{server_answer}"')
    else:
        ora_success, server_answer = await auth_oracle(session.user, session.password, session)
        if ora_success:
            if not session.user.lower() == 'em':
                log.info(f'Successful local login : {session}')
            session.db_conn = server_answer
        else:
            error = server_answer
            log.info(f'Access denied : {session}; error message = "{server_answer}"')

    if not error:
        if 'zlib' in session.required_filters:
            await session.write_line('* FILTER zlib')
            await session.send_good_result(message)
            z_memlevel = 8 if 'z_memLevel' not in session.oragate_cfg else session.oragate_cfg['z_memLevel']
            session.ziper = zlib.compressobj(zlib.Z_BEST_SPEED, zlib.DEFLATED, zlib.MAX_WBITS, memLevel=z_memlevel)
        else:
            await session.send_good_result(message)
    else:
        await session.send_bad_result(error)


def gen_oracle_credentials(ldap_guid: str, key: str) -> tuple:
    def baseN(num, b, numerals='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_'):
        return ((num == 0) and numerals[0]) or (baseN(num // b, b, numerals).lstrip(numerals[0]) + numerals[num % b])

    return f'L0_{baseN(int(ldap_guid, 16), 37)}', f'P0_{baseN(int(hashlib.md5((ldap_guid + key).encode()).hexdigest(), 16), 37)}'


def auth_ldap(login: str, password: str, server: dict):
    log = logging.getLogger('auth_ldap')
    ldap_filter = server['filter_users'].format(login)
    connect = ldap.initialize(f'ldap://{server["host"]}')
    connect.set_option(ldap.OPT_REFERRALS, 0)
    connect.simple_bind_s(server['bind_dn'], server['password'])
    answers = connect.search_s(server['base_user_dn'], ldap.SCOPE_SUBTREE, ldap_filter, ['ObjectGUID'])
    user_found = None
    for asnwer in answers:
        if asnwer[0] is not None:
            user_found, user_dn, objectGUID = True, asnwer[0], uuid.UUID(bytes_le=asnwer[1]['objectGUID'][0]).hex.upper()
            break

    if user_found:
        try:
            connect.simple_bind_s(user_dn, password)
            connect.unbind()
            return True, objectGUID
        except ldap.INVALID_CREDENTIALS as e:
            log.error(e)
            return False, 'Неверно имя пользователя/пароль; вход в систему запрещается'
        except Exception as e:
            return False, str(e)
    else:
        return False, f'person ({login}) not found'


async def auth_oracle(user: str, password, session: EqmUserSession):
    loop = asyncio.get_event_loop()
    try:
        conn = await loop.run_in_executor(None, functools.partial(cx_Oracle.connect, user=user,
                                                                  password=password,
                                                                  threaded=True,
                                                                  encoding='UTF-8',
                                                                  dsn=session.oragate_cfg['oracle']['dsn']))
        if user.lower() == 'em':
            return True, conn
        with conn.cursor() as cur:
            r = cur.execute('SELECT session_id FROM user_sessions WHERE session_id = (SELECT get_session_id FROM dual)')
            if r:
                session.session_id = r.fetchall()[0][0]
            else:
                return True, conn

            r = cur.execute("""select p.personal_id,
                       nvl(p.user_active, '0') user_active,
                       a.application_id,
                       (select 1
                          from os_lib.user_app_belong_to
                         where application_id = a.application_id
                           and personal_id = p.personal_id) apal
                  from dual
                  left outer join os_lib.personal p
                    on (upper(p.user_login) = user)
                  left outer join os_lib.applications a
                    on (a.name = :app)""", {'app': session.app})
            if r:
                result = default_output(r)
                if result['user_active'] == 0:
                    return False, f'{session.user}  blocked.'
                if not result['application_id']:
                    return False, f'Application {session.app} not found.'
                if not result['apal']:
                    return False, f'User {session.user} does not have access to {session.app}'
                session.personal_id = result['personal_id']
            else:
                return False, f'{session.user}  not in personal.'
            print(session.version)
            cur.execute('UPDATE user_sessions SET personal_id = :personal_id, pid=:pid, protocol=:protocol, application_ver=:app_ver, '
                        'application_id = (SELECT application_id FROM applications WHERE name=:app), foreign_ip=:peer_name, local_ip=:local_ip, '
                        'session_guid=:app_session_id WHERE session_id=:session_id',
                        {'personal_id': session.personal_id, 'pid': os.getpid(), 'protocol': session.v, 'app_ver': session.version,
                         'app': session.app,
                         'peer_name': f'{session.peer_ip}:{session.peer_port}', 'local_ip': session.local_ip, 'app_session_id': session.app_session_id,
                         'session_id': session.session_id})
            conn.commit()
            session.updated = True

    except Exception as e:
        return False, str(e)
    return True, conn

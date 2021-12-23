import hashlib
import logging
import os
import re
import uuid
import zlib

import cx_Oracle
import ldap

from models.eqm_user_session import EqmUserSession, sync_to_async


def default_output(cur: cx_Oracle.Cursor):
    """
    default output of fetch
    :param cur: cx_Oracle.Cursor
    :return: list of dicts or {} if cursor is empty
    """
    columns = [col[0].lower() for col in cur.description]
    cur.rowfactory = lambda *args: dict(zip(columns, args))
    result = [row for row in cur.fetchall()] if cur else {}
    if len(result) == 1:
        result = result[0]
    return result


async def doauth(login_str: str, session: EqmUserSession):
    """
    Perform login attempt
    :param login_str: login string
    :param session: EqmUserSession
    :return: False/True, error(str)/session_parameters(dict)
    """
    log = logging.getLogger('main')
    log_extra = dict(unique_name='auth')
    message = ''
    error = None

    login_dict = {i.group('key'): i.group('value') for i in
                  re.finditer(r'(?P<key>\w+)="(?P<value>.*?)"\s', login_str, re.MULTILINE)}
    session.update(**login_dict)
    if 'ldap' in session.oragate_cfg:
        ldap_success, server_answer = await auth_ldap(session.user, session.password, session.oragate_cfg['ldap'])
        if session.oragate_cfg['ldap_auth_only']:
            if ldap_success:
                message = f'redirect="{session.oragate_cfg["ORAGATE_REDIRECT"]}" ldap_guid="{server_answer}"'
                log.info(f'Successful ldap-auth-only : {session} ldap_guid = {server_answer}', extra=log_extra)
            else:
                error = server_answer
                log.info(f'Access denied : {session}; error message = "{server_answer}"', extra=log_extra)
        else:
            if ldap_success:
                log.info(f'Successful ldap login : {session}', extra=log_extra)
                session.ora_user, session.password = gen_oracle_credentials(server_answer, session.oragate_cfg['ldap']['key'])
                ora_success, server_answer = await auth_oracle(session.ora_user, session.password, session)
                if ora_success:
                    session.db_conn = server_answer
                else:
                    error = server_answer
            else:
                error = server_answer
                log.info(f'Access denied : {session}; error message = "{server_answer}"', extra=log_extra)
    else:
        ora_success, server_answer = await auth_oracle(session.user, session.password, session)
        if ora_success:
            if not session.user.lower() == 'em':
                log.info(f'Successful local login : {session}', extra=log_extra)
            session.db_conn = server_answer
        else:
            error = server_answer
            log.info(f'Access denied : {session}; error message = "{server_answer}"', extra=log_extra)

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


@sync_to_async
def auth_ldap(login: str, password: str, server: dict):
    log = logging.getLogger('main')
    log_extra = dict(unique_name='auth_ldap')
    ldap_filter = server['filter_users'].format(login)
    connect = ldap.initialize(f'ldap://{server["host"]}')
    connect.set_option(ldap.OPT_REFERRALS, 0)
    connect.simple_bind_s(server['bind_dn'], server['password'])
    answers = connect.search_s(server['base_user_dn'], ldap.SCOPE_SUBTREE, ldap_filter, ['ObjectGUID'])
    user_found = None
    for answer in answers:
        if answer[0] is not None:
            user_found, user_dn, objectGUID = True, answer[0], uuid.UUID(bytes_le=answer[1]['objectGUID'][0]).hex.upper()
            break

    if user_found:
        try:
            connect.simple_bind_s(user_dn, password)
            connect.unbind()
            return True, objectGUID
        except ldap.INVALID_CREDENTIALS as e:
            log.error(e, extra=log_extra)
            return False, 'Неверно имя пользователя/пароль; вход в систему запрещается'
        except Exception as e:
            return False, str(e)
    else:
        return False, f'person ({login}) not found'


@sync_to_async
def auth_oracle(user: str, password, session: EqmUserSession):
    conn = None
    try:
        conn = session.oragate_cfg['pool'].acquire(user=user, password=password)
        # conn = cx_Oracle.connect(user=user,
        #                          password=password,
        #                          threaded=True,
        #                          encoding='UTF-8',
        #                          dsn=session.oragate_cfg['oracle']['dsn'])
        if session.app == 'ojobd':
            conn.call_timeout = 10 * 60 * 60 * 1000  # 10 hours
        else:
            conn.call_timeout = session.call_timeout
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
                    session.oragate_cfg['pool'].release(conn)
                    return False, f'{session.user}  blocked.'
                if not result['application_id']:
                    session.oragate_cfg['pool'].release(conn)
                    return False, f'Application {session.app} not found.'
                if not result['apal']:
                    session.oragate_cfg['pool'].release(conn)
                    return False, f'User {session.user} does not have access to {session.app}'
                session.personal_id = result['personal_id']
            else:
                session.oragate_cfg['pool'].release(conn)
                return False, f'{session.user} not in personal.'

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
        if conn:
            session.oragate_cfg['pool'].release(conn)
        return False, str(e)
    return True, conn


async def recover_passw(message: str, session: EqmUserSession):
    log = logging.getLogger('main')
    log_extra = dict(unique_name='recover_passw')
    log.debug(message, extra=log_extra)
    login = re.search(r'^RECOVER login="(\w+)"', message).group(1)
    if not login:
        await session.send_bad_result('incorrect login')
        return

    error = await recover_oracle(login, session.oragate_cfg['oracle']['dsn'])
    if error:
        await session.send_bad_result(error)
    await session.send_good_result()


@sync_to_async
def recover_oracle(login: str, dsn):
    log = logging.getLogger('main')
    log_extra = dict(unique_name='recover_oracle')
    try:
        with cx_Oracle.connect(user='em', password='em_server_access', dsn=dsn, encoding="UTF-8") as conn:
            with conn.cursor() as cur:
                cur.execute('BEGIN os_lib.asys_utils.p_change_password(:login); END;', login=login)
                conn.commit()

    except cx_Oracle.DatabaseError as e:
        log.error(e, extra=log_extra)
        error, = e.args
        msg = re.search(r'^ORA.\d+:\s(.*)', error.message)
        msg = msg.group(1) if msg else error.message
        return msg

    except Exception as e:
        log.error(e)
        return str(e)

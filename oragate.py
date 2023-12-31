import socket
import threading
from datetime import datetime, timedelta
import hashlib
import logging
import logging.handlers
import os
import re
import socketserver
import uuid
import zlib
from typing import Optional
from threading import Timer
import oracledb as cx_Oracle
import ldap

from config import Config

# lib_dir = r'C:\instantclient_21_3'
lib_dir = r'/usr/lib/oracle/21/client64/lib'
cx_Oracle.init_oracle_client(lib_dir)

datatypes = {cx_Oracle.DB_TYPE_BINARY_DOUBLE: 'N',
             cx_Oracle.DB_TYPE_BINARY_FLOAT: 'N',
             cx_Oracle.DB_TYPE_BFILE: 'BLOB',
             cx_Oracle.DB_TYPE_RAW: 'RAW',
             cx_Oracle.DB_TYPE_LONG_RAW: 'LONG_RAW',
             cx_Oracle.DB_TYPE_BLOB: 'BLOB',
             cx_Oracle.DB_TYPE_CLOB: 'CLOB',
             cx_Oracle.DB_TYPE_DATE: 'DT',
             cx_Oracle.DB_TYPE_TIMESTAMP: 'DT',
             cx_Oracle.DB_TYPE_INTERVAL_DS: 'DT',
             cx_Oracle.DB_TYPE_VARCHAR: 'W',
             cx_Oracle.DB_TYPE_NVARCHAR: 'W',
             cx_Oracle.DB_TYPE_LONG: 'LONG',
             cx_Oracle.DB_TYPE_ROWID: 'W',
             cx_Oracle.DB_TYPE_CHAR: 'W'}

disconnect_errors = \
    ('ORA-03113',  # end-of-file on communication channel
     'ORA-03114',  # not connected to ORACLE
     'ORA-01012',  # not logged on
     'ORA-02396',  # exceeded maximum idle time, please connect again.
     'ORA-02399',  # exceeded maximum connect time, you are being logged off
     'ORA-03135',  # connection lost contact
     'ORA-00028',  # your session has been killed
     'ORA-04061',  # Existing state of string has been invalidated
     'ORA-12599',  # TNS:cryptographic checksum mismatch
     'DPI-1080',  # connection was closed by ORA-XXXXX
     'DPI-1010',  # not connected
     'DPY-4011',  # the database or network closed the connection
     )

empty_lob = {cx_Oracle.DB_TYPE_CLOB: 'empty_clob()', cx_Oracle.DB_TYPE_BLOB: 'empty_blob()'}

special_chars = {chr(n): f'\\{n:02X}' for n in range(0, 32)}

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)


def except_hook(args):
    exc_type, exc_value, exc_traceback, thread = args
    logging.debug(f'Exception in {thread.name}: {str(exc_value)}')


threading.excepthook = except_hook


def special_encode(input_str: str):
    input_str = input_str.replace('\\', '\\\\').replace('\\', '\\\\')
    for c in special_chars:
        input_str = input_str.replace(c, special_chars[c])
    input_str = input_str.replace(',', '\\\\,')
    return input_str


def get_column_type(name, col_type, display_size, internal_size, precision, scale, null_ok):
    name = special_encode(name)
    if col_type == cx_Oracle.DB_TYPE_NUMBER:
        return f'{name},N' if scale else f'{name},I'
    else:
        return f'{name},{datatypes[col_type]}'


def oragate_rowfactory(*values):
    return_list = []
    for value in values:
        if isinstance(value, str):
            return_list.append(special_encode(value))
        elif isinstance(value, (int, float)):
            return_list.append(str(value))
        elif isinstance(value, (datetime, timedelta)):
            return_list.append(datetime.strftime(value, '%Y%m%d_%H%M%S'))
        else:
            return_list.append('')
    return ','.join(return_list)


def gen_oracle_credentials(ldap_guid: str, key: str) -> tuple:
    def baseN(num, b, numerals='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_'):
        return ((num == 0) and numerals[0]) or (baseN(num // b, b, numerals).lstrip(numerals[0]) + numerals[num % b])

    return f'L0_{baseN(int(ldap_guid, 16), 37)}', f'P0_{baseN(int(hashlib.md5((ldap_guid + key).encode()).hexdigest(), 16), 37)}'


def format_bind_value(in_str: str):
    out_str = in_str.replace('\\,', ',').replace('\\\\', '\\')
    if out_str.lower() == 'null':
        return None
    if re.match(r'\d{8}_\d{6}', out_str):
        return datetime.strptime(out_str, '%Y%m%d_%H%M%S')
    elif re.match(r'^\d+\.\d+$', out_str):
        return float(out_str)
    else:
        return out_str


class OragateRequestHandler(socketserver.BaseRequestHandler):
    # user attrs
    __slots__ = (
    'user', 'ora_user', 'password', 'app', 'ldap_guid', 'version', 'required_filters', 'desired_filters', 'local_ip',
    'peer_ip', 'peer_port', 'app_session_id', 'session_id', 'personal_id', 'packet_size')
    cfg: Config
    recv_buff_size = 2 ** 13  # 8 KiB
    # End of response to successfully processed request.
    _good_result = '+OK'
    # End of response to unsuccessfully processed request.
    _bad_result = '-ERROR'
    eof = '\r\n'
    # buffer size for sending packets in SQL
    buffer_size = 2 ** 17  # 128 KB
    #  amount of time (in milliseconds) that a single round-trip to the database may take before a timeout will occur.
    call_timeout = 30 * 60 * 1000  # 0.5 hour. actually, not used
    db_conn: Optional[cx_Oracle.Connection]
    ziper = None
    z_memlevel = 8
    log: logging.Logger
    protocol_version = 'v3_proto'

    @property
    def session(self):
        return f'user = {self.user}; application = {self.app}; filters = {self.required_filters}; remote host = {self.local_ip}'

    @property
    def peer_name(self):
        return ':'.join(str(i) for i in self.client_address)

    def start_session_log(self):
        self.log.handlers.clear()
        h = logging.FileHandler(filename=f'session_logs/{self.session_id}.log')
        h.setFormatter(logging.Formatter('%(asctime)s - %(process)d - %(funcName)s - %(message)s', "%Y-%m-%d %H:%M:%S"))
        self.log.addHandler(h)

        self.log.setLevel('DEBUG')
        self.log.propagate = False

    def readcommand(self):
        # Helper function to recv until eof
        data = bytearray()
        while True:
            packet = self.request.recv(self.recv_buff_size)
            if not packet:
                return None  # socket closed
            data.extend(packet)
            if packet.endswith(self.eof.encode()):
                break
        for c in special_chars:
            data = data.replace(special_chars[c].encode(), c.encode())
        return data.decode().replace('\\\\', '\\')

    def handle(self):
        self.cfg = self.server.cfg
        self.request.settimeout(self.cfg.client_timeout)
        self.log = logging.getLogger(self.peer_name)
        try:
            while True:
                data = self.readcommand()
                if not data:
                    self.log.debug('disconnected normally')
                    break
                self.log.debug(f'rx: {data.__repr__()}')

                if data.startswith('LOGIN'):
                    self.doauth(data)
                    if self.cfg.session_logs and self.user.lower() != 'em':
                        self.start_session_log()
                        self.log.debug(f'{self.session} session_id={self.session_id} personal_id={self.personal_id}')
                elif data.startswith('PING'):
                    self.send_good_result()
                elif data.startswith('SQL'):
                    self.sql_handle(data)
                elif data.startswith(('SELECT_LOB', 'UPDATE_LOB')):
                    self.lob_handle(data)
                elif data.startswith('RECOVER'):
                    self.recover_passw(data)
                elif data.startswith('PROXY'):
                    self.proxy_handle(data)
                else:
                    self.send_bad_result()

        except BaseException as e:
            self.log.log(19, f"disconnected: {e}")
            self.send_bad_result(str(e))

    def apply_filters(self, data: bytes):
        if self.ziper:
            data = self.ziper.compress(data)
            data += self.ziper.flush(zlib.Z_SYNC_FLUSH)
        return data

    def send_good_result(self, msg=''):
        """
        send ok message
        :param msg: message
        """
        msg = ' ' + msg if msg else msg
        msg = f'{self._good_result}{self.wrap_line(msg)}'.encode()
        msg = self.apply_filters(msg)
        self.request.sendall(msg)

    def send_bad_result(self, msg=''):
        """
        send error message
        :param msg: message
        """
        msg = ' ' + msg if msg else msg
        msg = f'{self._bad_result}{self.wrap_line(msg)}'.encode()
        msg = self.apply_filters(msg)
        self.request.sendall(msg)

    def wrap_line(self, msg: str):
        """
        returns msg with eof at end
        :param msg: message
        :return: wrapped msg
        """
        return f'{msg}{self.eof}'

    def write_line(self, msg: str):
        """
        encode and write line with eof at end
        :param msg: message
        """
        msg = self.wrap_line(msg).encode()
        msg = self.apply_filters(msg)
        self.request.sendall(msg)

    def write_binary(self, msg: bytes):
        """
        encode and write line with eof at end
        :param msg: message
        """
        msg = self.apply_filters(msg)
        self.request.sendall(msg)

    def doauth(self, login_str: str):
        """
        Perform login attempt
        :param login_str: login string
        :return: False/True, error(str)/session_parameters(dict)
        """
        message = ''
        error = None

        login_dict = {i.group('key'): i.group('value') for i in
                      re.finditer(r'(?P<key>\w+)="(?P<value>.*?)"\s', login_str, re.MULTILINE)}

        for k, v in login_dict.items():
            if k in self.__slots__:
                setattr(self, k, v if isinstance(v, str) else v)

        if self.cfg.ldap:
            ldap_success, server_answer = self.auth_ldap()
            if self.cfg.ldap.ldap_auth_only:
                if ldap_success:
                    message = f'redirect="{self.cfg.ORAGATE_REDIRECT}" ldap_guid="{server_answer}"'
                    self.log.info(f'Successful ldap-auth-only : {self.session} ldap_guid = {server_answer}')
                else:
                    error = server_answer
                    self.log.info(f'Access denied : {self.session}; error message = "{server_answer}"')
            else:
                if ldap_success:
                    self.ora_user, self.password = gen_oracle_credentials(server_answer, self.cfg.ldap.key)
                    ora_success, server_answer = self.auth_oracle()
                    if ora_success:
                        self.db_conn = server_answer
                        self.log.info(f'Successful ldap login : {self.session}')
                    else:
                        error = server_answer
                        self.log.info(f'Unsuccessful ldap login : {self.session}; error message = "{server_answer}"')
                else:
                    error = server_answer
                    self.log.info(f'Access denied : {self.session}; error message = "{server_answer}"')
        else:
            self.ora_user = self.user
            ora_success, server_answer = self.auth_oracle()
            if ora_success:
                if not self.user.lower() == 'em':
                    self.log.info(f'Successful local login : {self.session}')
                self.db_conn = server_answer
            else:
                error = server_answer
                self.log.info(f'Access denied : {self.session}; error message = "{server_answer}"')

        if not error:
            if self.app == 'EM.Starter':
                self.request.settimeout(28800)  # 8h

            if 'zlib' in self.required_filters:
                self.write_line('* FILTER zlib')
                self.send_good_result(message)
                self.ziper = zlib.compressobj(zlib.Z_BEST_SPEED, zlib.DEFLATED, zlib.MAX_WBITS,
                                              memLevel=self.z_memlevel)
            else:
                self.send_good_result(message)
        else:
            self.send_bad_result(error)
            raise AssertionError('Not logged in')

    def recover_passw(self, message: str):
        self.log.debug(message)
        login = re.search(r'^RECOVER login="(\w+)"', message, re.DOTALL).group(1)
        if not login:
            self.send_bad_result('incorrect login')
            return

        error = self.recover_oracle()
        if error:
            self.send_bad_result(error)
        self.send_good_result()
        self.log.debug('tx sent')

    def sql_handle(self, message: str):
        sql, full, binds_str = re.findall('query="(.*)" bind_values(_full)?="(.*)"', message, re.DOTALL)[0]
        if full:
            raw_binds = re.split(r'(?<!\\),', binds_str)
            binds = dict(
                zip([key[1::] for key in raw_binds[::2]], [format_bind_value(value) for value in raw_binds[1::2]]))
        else:
            for i in range(len(re.findall('\?', sql))):
                sql = sql.replace('?', f':{i}', 1)
            binds = binds_str.split(',') if binds_str else {}
        try:
            with self.db_conn.cursor() as cur:
                cur.arraysize = int(self.packet_size)
                cur.prefetchrows = cur.arraysize + 1

                t = Timer(self.cfg.oracle.sql_timeout, self.db_conn.cancel)

                if self.user.lower() != 'em':
                    t.start()
                try:
                    r = cur.execute(sql, binds)
                finally:
                    if t.is_alive():
                        t.cancel()
                if r:
                    header = '* HEADER ' + ','.join([get_column_type(*col) for col in r.description])
                    self.write_line(header)
                    r.rowfactory = oragate_rowfactory
                    buffer = bytearray()
                    while True:
                        rows = cur.fetchmany(int(self.packet_size))
                        if not rows:
                            buffer.extend(self.wrap_line(self._good_result).encode())
                            break
                        buffer.extend(self.wrap_line(f'* PACKET {len(rows)}').encode())
                        for row in rows:
                            if len(buffer) + len(row) >= self.buffer_size:
                                self.write_binary(buffer)
                                buffer.clear()
                            buffer += self.wrap_line(f'* {row}').encode()
                    if buffer:
                        self.write_binary(buffer)
                    del buffer, rows, r
                else:
                    self.write_line(f'* {str(cur.rowcount)}')
                    self.send_good_result()
            self.log.debug('tx sent')
        except cx_Oracle.DatabaseError as e:
            self.handle_oracle_error(e)

        except Exception as e:
            self.log.exception(e)
            self.send_bad_result('internal error')

    def lob_handle(self, message):
        # self.log.debug(message)
        try:
            command = message[:10]
            table = re.findall('table="([^"]*)"', message, re.DOTALL)[0]
            field = re.findall('field="([^"]*)"', message, re.DOTALL)[0]
            where = re.findall('where="([^"]*)"', message, re.DOTALL)[0]
            with self.db_conn.cursor() as cur:
                cur.prefetchrows = 0
                cur.arraysize = 1
                if command == 'UPDATE_LOB':
                    lob_size = int(re.findall('size="(\d+)"', message)[0])
                    # getting lob type via select_sql
                    select_sql = f'SELECT {field} from {table} where {where}'
                    cur.execute(select_sql)
                    lob_type = cur.description[0][1]
                    lob_var = cur.var(lob_type)
                    # updating lob via update_sql
                    update_sql = f'UPDATE {table} set {field}={empty_lob[lob_type]} where {where} returning {field} into :lob_var'
                    cur.execute(update_sql, lob_var=lob_var)
                    lob, = lob_var.getvalue()
                    self.write_line('* Ready')
                    chunk = lob.getchunksize() * 8
                    offset = 1
                    lob.open()
                    while offset < lob_size:
                        data = self.request.recv(chunk)
                        if data:
                            lob.write(data, offset)
                        offset += len(data)
                    lob.close()

                if command == 'SELECT_LOB':
                    sql = f'SELECT {field} from {table} where {where}'
                    cur.execute(sql)
                    lob = cur.fetchone()
                    if lob and lob[0]:  # fix for empty lobs
                        self.write_line('* Ready')
                        offset = 1
                        max_chunk = 32767
                        chunk = max_chunk
                        if lob[0].type == cx_Oracle.DB_TYPE_CLOB:
                            chunk = 28000

                        while True:
                            raw_data = lob[0].read(offset, chunk)
                            data = raw_data.encode() if isinstance(raw_data, str) else raw_data

                            if len(raw_data) < chunk:
                                data_size = max_chunk + 1 + len(data)
                            else:
                                data_size = len(data)
                            self.write_binary(data_size.to_bytes(2, 'little'))
                            self.write_binary(data)
                            if len(data) < chunk:
                                break
                            offset += len(data)
            self.send_good_result()
            self.log.debug('tx sent')
        except cx_Oracle.DatabaseError as e:
            self.handle_oracle_error(e)

        except Exception as e:
            self.log.exception(e)
            self.send_bad_result('internal error')

    def auth_ldap(self):
        try:
            ldap_filter = self.cfg.ldap.filter_users.format(self.user)
            connect = ldap.initialize(self.cfg.ldap.host)
            connect.set_option(ldap.OPT_REFERRALS, 0)
            connect.simple_bind_s(self.cfg.ldap.bind_dn, self.cfg.ldap.password)
            answers = connect.search_s(self.cfg.ldap.base_user_dn, ldap.SCOPE_SUBTREE, ldap_filter, ['ObjectGUID'])
        except ldap.LDAPError as e:
            self.log.error(e)
            return False, f'Ldap initialize/bind DN={self.cfg.ldap.bind_dn} server returned error: {e}'

        user_found = None
        for answer in answers:
            if answer[0] is not None:
                user_found, user_dn, objectGUID = True, answer[0], uuid.UUID(
                    bytes_le=answer[1]['objectGUID'][0]).hex.upper()
                break

        if user_found:
            try:
                connect.simple_bind_s(user_dn, self.password)
                connect.unbind()
                return True, objectGUID
            except ldap.INVALID_CREDENTIALS as e:
                return False, 'ORA-01017: Неверно имя пользователя/пароль; вход в систему запрещается'
            except Exception as e:
                self.log.error(e)
                return False, str(e)
        else:
            return False, f'person ({self.user}) not found'

    def auth_oracle(self):
        try:
            conn = cx_Oracle.connect(user=self.ora_user,
                                     password=self.password,
                                     encoding='UTF-8',
                                     threaded=True,
                                     stmtcachesize=0,
                                     dsn=self.cfg.oracle.dsn)

            if self.user.lower() == 'em':
                return True, conn
            with conn.cursor() as cur:
                cur.prefetchrows = 1
                cur.arraysize = 1
                r = cur.execute(
                    'SELECT session_id FROM user_sessions WHERE session_id = (SELECT get_session_id FROM dual)')
                if r:
                    self.session_id = r.fetchall()[0][0]
                    self.log.name += f' {self.session_id}'
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
                        on (a.name = :app)""", {'app': self.app})
                if r:
                    cur.rowfactory = lambda *args: dict(zip([col[0].lower() for col in cur.description], args))
                    result = cur.fetchone()
                    if result['user_active'] == 0:
                        return False, f'{self.user}  blocked.'
                    if not result['application_id']:
                        return False, f'Application {self.app} not found.'
                    if not result['apal']:
                        return False, f'User {self.user} does not have access to {self.app}'
                    self.personal_id = result['personal_id']
                    self.log.name += f':{self.personal_id}'
                else:
                    return False, f'{self.user} not in personal.'

                cur.execute(
                    'UPDATE user_sessions SET personal_id = :personal_id, pid=:pid, protocol=:protocol, application_ver=:app_ver, '
                    'application_id = (SELECT application_id FROM applications WHERE name=:app), foreign_ip=:peer_name, local_ip=:local_ip, '
                    'session_guid=:app_session_id WHERE session_id=:session_id',
                    {'personal_id': self.personal_id, 'pid': os.getpid(), 'protocol': self.protocol_version,
                     'app_ver': self.version,
                     'app': self.app, 'peer_name': self.peer_name, 'local_ip': self.local_ip,
                     'app_session_id': self.app_session_id,
                     'session_id': self.session_id})
                conn.commit()

        except Exception as e:
            return False, str(e)
        return True, conn

    def recover_oracle(self):
        try:
            with cx_Oracle.connect(user='em', password='em_server_access', dsn=self.cfg.oracle.dsn,
                                   encoding="UTF-8") as conn:
                with conn.cursor() as cur:
                    cur.execute('BEGIN os_lib.asys_utils.p_change_password(:login); END;', login=self.user)
                    conn.commit()

        except cx_Oracle.DatabaseError as e:
            error, = e.args
            msg = re.search(r'^ORA.\d+:\s(.*)', error.message)
            msg = msg.group(1) if msg else error.message
            return msg

        except Exception as e:
            return str(e)

    def proxy_handle(self, message: str):
        def proxy_listner(sock: socket.socket):
            self.log.debug('start proxy listner thread')
            try:
                while True:
                    data = sock.recv(self.recv_buff_size)
                    if not data:
                        break  # socket closed
                    self.write_binary(data)
            except Exception as e:
                self.log.exception(e)
            self.log.debug('stop proxy listner thread')

        # self.log.debug(message)
        try:
            host, port = re.search(r'PROXY (.+):(\d+)', message, re.DOTALL).groups()
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.connect((host, int(port)))
            self.send_good_result()
            proxy_thread = threading.Thread(target=proxy_listner, args=(proxy_sock,), daemon=True)
            proxy_thread.start()
            try:
                while True:
                    request = self.request.recv(self.recv_buff_size)
                    if not request:
                        break  # socket closed
                    proxy_sock.sendall(request)
            finally:
                proxy_sock.close()
                proxy_thread.join()
            self.log.debug('tx sent')
        except Exception as e:
            self.send_bad_result('Error proxy connection, see log for detail')
            self.log.exception(e)

    def handle_oracle_error(self, e: cx_Oracle.DatabaseError):
        er, = e.args
        err = str(e)
        self.log.debug(err)
        ora_error = re.search(r'^(\w{3}-\d+):.*', er.message).group(1)
        # new line char cause EM to faults
        for c in special_chars:
            err = err.replace(c, special_chars[c])
        self.send_bad_result(err)
        if ora_error in disconnect_errors:
            raise e  # Cause disconnect

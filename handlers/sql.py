import asyncio
import datetime
import functools
import logging
import re
import traceback
import cx_Oracle
from models.eqm_user_session import EqmUserSession

special_chars = {'\n': r'\0A', '\r': r'\0D', '\t': r'\09'}


def special_encode(input_str):
    input_str = input_str.replace('\\', '\\\\').replace('\\', '\\\\')
    for c in special_chars:
        input_str = input_str.replace(c, special_chars[c])
    input_str = input_str.replace(',', '\\,')
    return input_str


def special_decode(input_str):
    for c in special_chars:
        input_str = input_str.replace(special_chars[c], c)
    input_str = input_str.replace('\\,', ',')
    return input_str.replace('\\\\', '\\')


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
             cx_Oracle.DB_TYPE_LONG: 'LONG',
             cx_Oracle.DB_TYPE_ROWID: 'W',
             cx_Oracle.DB_TYPE_CHAR: 'W'}


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
        elif isinstance(value, (datetime.datetime, datetime.timedelta)):
            return_list.append(datetime.datetime.strftime(value, '%Y%m%d_%H%M%S'))
        else:
            return_list.append('')
    return ','.join(return_list)


def format_bind_value(str: str):
    str = special_decode(str)
    if str == 'null':
        return None
    if re.match(r'\d{8}_\d{6}', str):
        return datetime.datetime.strptime(str, '%Y%m%d_%H%M%S')
    elif re.match(r'^\d+\.\d+$', str):
        return float(str)
    elif re.match(r'^\d+$', str):
        return int(str)
    else:
        return str


async def sql_handle(message: str, session: EqmUserSession):
    loop = asyncio.get_event_loop()
    log = logging.getLogger('sql_handle')
    sql, full, binds_str = re.findall('query="(.*)" bind_values(_full)?="(.*)"', message)[0]
    for c in special_chars:
        sql = sql.replace(special_chars[c], c)
    sql = sql.replace('\\\\', '\\').replace('\\\\', '\\')
    raw_binds = re.split(r'(?<!\\),', binds_str)
    binds = dict(zip([key[1::] for key in raw_binds[::2]], [format_bind_value(value) for value in raw_binds[1::2]]))
    log.debug(f'sql, binds = {sql, binds}')
    try:
        with session.db_conn.cursor() as cur:
            r = await loop.run_in_executor(None, functools.partial(cur.execute, sql, binds))
            if r:
                header = '* HEADER ' + ','.join([get_column_type(*col) for col in r.description])
                session.write_line(header)
                r.rowfactory = oragate_rowfactory
                while True:
                    rows = await loop.run_in_executor(None, functools.partial(cur.fetchmany, int(session.packet_size)))
                    if not rows:
                        await session.send_good_result()
                        break
                    session.write_line(f'* PACKET {len(rows)}')
                    for row in rows:
                        session.write_line(f'* {row}')
                    await session.writer.drain()
            else:
                await session.send_good_result(str(cur.rowcount))
    except Exception as e:
        log.error(str(e))
        log.debug(traceback.format_exc())
        await session.send_bad_result(str(e))


async def lob_handle(message: str, session: EqmUserSession):
    loop = asyncio.get_event_loop()
    log = logging.getLogger('sql_handle')
    try:
        command = message[:10]
        table = re.findall('table="([^"]*)"', message)[0]
        field = re.findall('field="([^"]*)"', message)[0]
        where = re.findall('where="([^"]*)"', message)[0]

        if command == 'UPDATE_LOB':
            lob_size = int(re.findall('size="(\d+)"', message)[0])

            sql = f'UPDATE {table} set {field}=empty_blob() where {where} returning {field} into :lob_var'
            log.debug(sql)
            with session.db_conn.cursor() as cur:
                lob_var = cur.var(cx_Oracle.DB_TYPE_BLOB)
                await loop.run_in_executor(None, functools.partial(cur.execute, sql, lob_var=lob_var))
                lob, = lob_var.getvalue()
                await session.send_line('* READY')
                chunk = lob.getchunksize() * 8
                offset = 1
                lob.open()
                while offset < lob_size:
                    data = await session.reader.read(chunk)
                    if data:
                        await loop.run_in_executor(None, functools.partial(lob.write, data, offset))
                    offset += len(data)
        elif command == 'SELECT_LOB':
            sql = f'SELECT {field} from {table} where {where}'
            log.debug(sql)
            with session.db_conn.cursor() as cur:
                await loop.run_in_executor(None, functools.partial(cur.execute, sql))
                lob, = await loop.run_in_executor(None, cur.fetchone)
                offset = 1
                chunk = 32767
                await session.send_line('* READY')
                while True:
                    data = lob.read(offset, chunk)
                    if data:
                        if len(data) < chunk:
                            data_size = chunk + 1 + len(data)
                            log.debug(f'send last chunk = {len(data)}')
                        else:
                            data_size = chunk
                            log.debug(f'send chunk = {data_size}')
                        session.writer.write(data_size.to_bytes(2, 'little'))
                        session.writer.write(data)
                        await session.writer.drain()
                    if len(data) < chunk:
                        break
                    offset += len(data)

        await session.send_good_result()
    except Exception as e:
        log.error(str(e))
        log.debug(traceback.format_exc())
        await session.send_bad_result(str(e))

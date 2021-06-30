import asyncio
import datetime
import functools
import logging
import re
import cx_Oracle
from models.eqm_user_session import EqmUserSession, special_decode, special_encode, special_chars

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

empty_lob = {cx_Oracle.DB_TYPE_CLOB: 'empty_clob()', cx_Oracle.DB_TYPE_BLOB: 'empty_blob()'}


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
    if str.lower() == 'null':
        return None
    if re.match(r'\d{8}_\d{6}', str):
        return datetime.datetime.strptime(str, '%Y%m%d_%H%M%S')
    elif re.match(r'^\d+\.\d+$', str):
        return float(str)
    # elif re.match(r'^\d+$', str):
    #    return int(str)
    else:
        return str


async def sql_handle(message: str, session: EqmUserSession):
    loop = asyncio.get_event_loop()
    log = logging.getLogger('sql_handle')
    log.debug(message)
    sql, full, binds_str = re.findall('query="(.*)" bind_values(_full)?="(.*)"', message)[0]
    raw_binds = re.split(r'(?<!\\),', binds_str)
    binds = dict(zip([key[1::] for key in raw_binds[::2]], [format_bind_value(value) for value in raw_binds[1::2]]))
    try:
        with session.db_conn.cursor() as cur:
            cur.prefetchrows = 1000
            cur.arraysize = 1000
            r = await loop.run_in_executor(None, functools.partial(cur.execute, special_decode(sql), binds))
            if r:
                header = '* HEADER ' + ','.join([get_column_type(*col) for col in r.description])
                await session.write_line(header)
                r.rowfactory = oragate_rowfactory
                buffer = bytearray()
                while True:
                    rows = await loop.run_in_executor(None, functools.partial(cur.fetchmany, int(session.packet_size)))
                    if not rows:
                        buffer += session.wrap_line(session.good_result).encode()
                        break
                    buffer += session.wrap_line(f'* PACKET {len(rows)}').encode()
                    for row in rows:
                        if len(buffer) + len(row) >= session.buffer_size:
                            await session.write_binary(buffer)
                            await session.writer.drain()
                            buffer = session.wrap_line(f'* {row}').encode()
                        else:
                            buffer += session.wrap_line(f'* {row}').encode()
                if buffer:
                    await session.write_binary(buffer)
                    await session.writer.drain()
                del buffer
            else:
                await session.write_line(f'* {str(cur.rowcount)}')
                await session.send_good_result()

    except cx_Oracle.DatabaseError as e:
        err = str(e)
        log.debug(err)
        # new line char cause EM to faults
        for c in special_chars:
            err = err.replace(c, special_chars[c])
        await session.send_bad_result(err)

    except Exception as e:
        log.error(e, exc_info=True)
        await session.send_bad_result('internal error')


async def lob_handle(message: str, session: EqmUserSession):
    loop = asyncio.get_event_loop()
    log = logging.getLogger('lob_handle')
    log.debug(message)
    try:
        command = message[:10]
        table = re.findall('table="([^"]*)"', message)[0]
        field = re.findall('field="([^"]*)"', message)[0]
        where = re.findall('where="([^"]*)"', message)[0]

        if command == 'UPDATE_LOB':
            lob_size = int(re.findall('size="(\d+)"', message)[0])
            with session.db_conn.cursor() as cur:
                # gettin' lob type via select_sql
                select_sql = f'SELECT {field} from {table} where {where}'
                await loop.run_in_executor(None, functools.partial(cur.execute, select_sql))
                lob_type = cur.description[0][1]
                lob_var = cur.var(lob_type)
                # updating lob via update_sql
                update_sql = f'UPDATE {table} set {field}={empty_lob[lob_type]} where {where} returning {field} into :lob_var'
                await loop.run_in_executor(None, functools.partial(cur.execute, update_sql, lob_var=lob_var))
                lob, = lob_var.getvalue()
                await session.send_line('* READY')
                chunk = lob.getchunksize() * 8
                offset = 1
                lob.open()
                while offset < lob_size:
                    data = await session.read_data(chunk)
                    if data:
                        await loop.run_in_executor(None, functools.partial(lob.write, data, offset))
                    offset += len(data)
                lob.close()
        elif command == 'SELECT_LOB':
            sql = f'SELECT {field} from {table} where {where}'
            with session.db_conn.cursor() as cur:
                await loop.run_in_executor(None, functools.partial(cur.execute, sql))
                lob, = await loop.run_in_executor(None, cur.fetchone)
                if lob:
                    offset = 1
                    chunk = 32767
                    await session.send_line('* READY')
                    while True:
                        data = await loop.run_in_executor(None, functools.partial(lob.read, offset, chunk))
                        if data:
                            if len(data) < chunk:
                                data_size = chunk + 1 + len(data)
                            else:
                                data_size = chunk
                            await session.write_binary(data_size.to_bytes(2, 'little'))
                            await session.write_binary(data)
                            await session.writer.drain()
                        if len(data) < chunk:
                            break
                        offset += len(data)

        await session.send_good_result()

    except cx_Oracle.DatabaseError as e:
        err = str(e)
        log.debug(e)
        # new line char cause EM to faults
        for c in special_chars:
            err = err.replace(c, special_chars[c])
        await session.send_bad_result(err)

    except Exception as e:
        log.error(e, exc_info=True)
        await session.send_bad_result('internal error')

import asyncio
import logging
from handlers import auth, sql
from models.eqm_user_session import EqmUserSession

# handler funcs
handlers = [{'prefix': 'LOGIN', 'function': auth.doauth},
            {'prefix': 'RECOVER', 'function': auth.recover_passw},
            {'prefix': 'SQL', 'function': sql.sql_handle},
            {'prefix': 'SELECT_LOB', 'function': sql.lob_handle},
            {'prefix': 'UPDATE_LOB', 'function': sql.lob_handle}]


async def client_connected(reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter, cfg: dict):
    """
    Main entrypoint for each connection
    """
    client = writer.get_extra_info('peername')
    session = EqmUserSession(peer_ip=client[0], peer_port=client[1], reader=reader, writer=writer, oragate_cfg=cfg)
    log = logging.getLogger('main')
    log_extra = dict(unique_name=f'Remote {client[0]}, {client[1]}')
    log.debug('connected', extra=log_extra)
    try:
        while True:
            # reading all incoming data
            data = await reader.readuntil(session.eof.encode())
            if not data:
                # client disconnected
                logging.debug('disconnected', extra=log_extra)
                break
            message = data.decode()
            # function logic
            for handler in handlers:
                if message.startswith(handler['prefix']):
                    await handler['function'](message, session)

    except (asyncio.IncompleteReadError, asyncio.CancelledError, asyncio.TimeoutError):
        pass
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        log.error(f"disconnected {str(e)}", extra=log_extra)
    except Exception as e:
        log.exception(e, extra=log_extra)
        await session.send_bad_result(str(e))

    writer.close()
    await writer.wait_closed()
    log.debug(f'Closed session {session}', extra=log_extra)

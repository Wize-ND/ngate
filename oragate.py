import asyncio
import logging
from handlers import auth, sql, encryption
from models.eqm_user_session import EqmUserSession
from async_timeout import timeout

# handler funcs
handlers = [{'prefix': 'LOGIN', 'function': auth.doauth},
            {'prefix': 'SQL', 'function': sql.sql_handle},
            {'prefix': 'SELECT_LOB', 'function': sql.lob_handle},
            {'prefix': 'UPDATE_LOB', 'function': sql.lob_handle},
            {'prefix': 'ENCRYPTED', 'function': encryption.start_encryption}]


async def client_connected(reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter, cfg: dict):
    """
    Main entrypoint for each connection
    """
    client = writer.get_extra_info('peername')
    session = EqmUserSession(peer_ip=client[0], peer_port=client[1], reader=reader, writer=writer, oragate_cfg=cfg)
    log = logging.getLogger(f'Remote {client[0]}, {client[1]}')
    log.debug(f"connected")
    try:
        async with timeout(session.max_life):
            while True:
                # reading all incoming data
                data = await reader.readuntil(session.eof.encode())
                if not data:
                    # client disconnected
                    log.debug(f"disconnected")
                    break
                if session.encryption_key:
                    data = session.decrypt_data(data)
                message = data.decode()
                # function logic
                for handler in handlers:
                    if message.startswith(handler['prefix']):
                        await handler['function'](message, session)
                del message, data

    except (asyncio.IncompleteReadError, asyncio.CancelledError, asyncio.TimeoutError):
        pass
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        log.error(f"disconnected {str(e)}")
    except Exception as e:
        log.error(e)
        await session.send_bad_result(str(e))
    finally:
        del session
        writer.close()

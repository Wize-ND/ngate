import asyncio
import logging
import traceback

from handlers import auth, sql
from models.eqm_user_session import EqmUserSession

# handler funcs
handlers = [{'prefix': 'LOGIN', 'function': auth.doauth},
            {'prefix': 'SQL', 'function': sql.sql_handle},
            {'prefix': 'SELECT_LOB', 'function': sql.lob_handle},
            {'prefix': 'UPDATE_LOB', 'function': sql.lob_handle}]


async def client_connected(reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter, cfg: dict):
    """
    Main entrypoint for each connection
    """
    client = writer.get_extra_info('peername')
    session = EqmUserSession(peer_ip=client[0], peer_port=client[1], reader=reader, writer=writer, oragate_cfg=cfg)
    log = logging.getLogger(f'Remote {client[0]}, {client[1]}')
    log.debug(f"connected")
    try:
        while True:
            # reading all incoming data
            data = await reader.readuntil(session.eof.encode())
            if not data:
                # client disconnected
                log.debug(f"disconnected")
                break
            message = data.decode()
            # function logic
            for handler in handlers:
                if message.startswith(handler['prefix']):
                    await handler['function'](message, session)
    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        log.error(str(e))
        log.debug(traceback.format_exc())
        await session.send_bad_result(str(e))
    finally:
        writer.close()

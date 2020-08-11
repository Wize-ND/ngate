import asyncio
import logging
from handlers import auth
from models.eqm_user_session import EqmUserSession


# handler funcs
handlers = [{'prefix': 'LOGIN', 'function': auth.doauth},
            {'prefix': 'SQL', 'function': None},
            {'prefix': 'SELECT_LOB', 'function': None},
            {'prefix': 'UPDATE_LOB', 'function': None}]


async def client_connected(reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter, cfg: dict):
    """
    Main entrypoint for each connection
    """
    client = writer.get_extra_info('peername')
    session = EqmUserSession(local_ip=client[0], local_port=client[1])
    log = logging.getLogger(f'remote {client[0]}, {client[1]}')
    log.debug(f"connected")
    try:
        while True:
            # reading all incoming data
            data = await reader.read(65535)
            if not data:
                # client disconnected
                log.debug("disconnected")
                break
            message = data.decode()

            log.debug(f"Received: {message!r}")
            # function logic
            for handler in handlers:
                if message.startswith(handler['prefix']):
                    await handler['function'](reader, writer, message, cfg, session)

            log.debug(f"Sending: {message!r}")
            writer.write(message.encode())
            await writer.drain()
    finally:
        writer.close()

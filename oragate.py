import asyncio
import logging


async def client_connected(reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter, cfg: dict):
    """
    Main entrypoint for each connection
    """
    client = writer.get_extra_info('peername')
    log = logging.getLogger(f'remote {client[0]},{client[1]}')
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

            # echo logic
            log.debug(f"Received: {message!r}")
            log.debug(f"Sending: {message!r}")
            writer.write(message.encode())
            await writer.drain()
    finally:
        writer.close()

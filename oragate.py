import asyncio
import logging


async def client_connected(reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter):
    """
    Main entrypoint for each connection
    """
    client = writer.get_extra_info('peername')
    logging.getLogger(str(client))
    try:
        while True:
            # reading all incoming data
            data = await reader.read(65535)
            if not data:
                # client disconnected
                print(f"client {client} disconnected")
                break
            message = data.decode()

            print(f"From {client!r} received {message!r} ")

            print(f"Send: {message!r}")
            writer.write(message.encode())
            await writer.drain()
    finally:
        writer.close()

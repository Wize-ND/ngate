import argparse
import asyncio
import logging
import os
import cx_Oracle
import yaml

# Args section
parser = argparse.ArgumentParser(description='oragate v2')
parser.add_argument('--config_file', '-c', help='config file, YAML format', default='oragate.yml')
parser.add_argument('--path', help="where to listen incoming requests (overrides config 'host/path' key) can be used Unix domain socket")
parser.add_argument('--port', help="where to listen incoming requests (overrides config 'port' key)")
parser.add_argument('--log_file', help="log filename (overrides config 'logging.filename' key)")

args = parser.parse_args()
cfg = yaml.safe_load(open(args.config_file))

if 'ora_service_name' in cfg['oracle']:
    dsn = cx_Oracle.makedsn(cfg['oracle']['ora_host'],
                            cfg['oracle']['ora_port'],
                            service_name=cfg['oracle']['ora_service_name'])
elif 'ora_tns_name' in cfg['oracle']:
    dsn = cfg['oracle']['ora_tns_name']
else:
    dsn = cx_Oracle.makedsn(cfg['oracle']['ora_host'],
                            cfg['oracle']['ora_port'],
                            sid=cfg['oracle']['ora_sid'])
cfg['oracle']['dsn'] = dsn

# logging
log_file = args.log_filename or cfg['logging']['filename']
logging.basicConfig(format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s: %(message)s',
                    level=cfg['logging']['level'],
                    filename=log_file)

async def main_handler(reader, writer):
    addr = writer.get_extra_info('peername')
    messages = []
    try:
        while True:
            data = await reader.read(65535)
            if not data:
                print(f"Close the connection {data}")
                break
            message = data.decode()
            messages.append(message)

            print(f"Received {message!r} from {addr!r}")

            print(f"Send: {message!r}. last messages: {messages}")
            writer.write(str(messages).encode())
            await writer.drain()

    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(
        main_handler, port=1976)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()


asyncio.run(main())

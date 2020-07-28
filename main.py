import argparse
import asyncio
import functools
import logging
import os
import signal
import traceback

import cx_Oracle
import yaml

from oragate import client_connected

# Args section
parser = argparse.ArgumentParser(description='oragate v2')
parser.add_argument('--config_file', '-c', help='config file, YAML format', default='oragate.yml')
parser.add_argument('--port', help="where to listen incoming requests (overrides config 'port' key)")
parser.add_argument('--log_file', help="log filename (overrides config 'logging.filename' key)")

args = parser.parse_args()
cfg = yaml.safe_load(open(args.config_file))
cfg['network']['port'] = cfg['network']['port'] or 1976

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
log_file = args.log_file or cfg['logging']['filename']
logging.basicConfig(format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s: %(message)s',
                    level=cfg['logging']['level'],
                    filename=log_file)


def clean_exit(signame, loop):
    logging.info(f'got signal {signame}, shutting down')
    loop.stop()


async def main():
    loop = asyncio.get_event_loop()
    # catch some termination signals
    try:
        for signame in {'SIGINT', 'SIGTERM'}:
            loop.add_signal_handler(getattr(signal, signame), functools.partial(clean_exit, signame, loop))
    except NotImplementedError:
        pass

    server = await asyncio.start_server(functools.partial(client_connected, cfg=cfg), port=cfg['network']['port'])
    logging.info(f'Start serving on {server.sockets[0].getsockname()}')
    async with server:
        await server.serve_forever()


try:
    asyncio.run(main())
except Exception as e:
    logging.error(f'Server shutdown due to error: {traceback.format_exc()}')
finally:
    logging.info('Server stopped')

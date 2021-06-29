import argparse
import asyncio
import functools
import logging
import signal
import sys

import yaml

import db
from oragate import client_connected
from pid_lock import check_lock, remove_lock

# Args section
parser = argparse.ArgumentParser(description='oragate v2')
parser.add_argument('--config_file', '-c', help='config file, YAML format (oragate.yml by default).', default='oragate.yml')
parser.add_argument('--port', help="where to listen incoming requests (overrides config 'network.port' key)")
parser.add_argument('--log_file', help="log file (overrides config 'logging.filename' key)")
parser.add_argument('--lock_file', help="lock file")
parser.add_argument('--ldap_auth_only', help="Mode ldap-auth-only ldap_config and config variable ORAGATE_REDIRECT required).", action='store_true')

args = parser.parse_args()
cfg = yaml.safe_load(open(args.config_file))
cfg['network']['port'] = args.port or cfg['network']['port'] or 1976
cfg['oracle']['dsn'] = db.get_oracle_dsn(cfg)
cfg['ldap_auth_only'] = args.ldap_auth_only
cfg['version'] = '3' or cfg['version']

# logging
log_handlers = []

log_file = args.log_file or cfg['logging']['filename'] if 'filename' in cfg['logging'] else None
if log_file:
    log_handlers.append(logging.FileHandler(filename=log_file, encoding='utf-8'))
if 'stdout' in cfg['logging']:
    log_handlers.append(logging.StreamHandler(stream=sys.stdout))
logging.basicConfig(format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s: %(message)s',
                    level=cfg['logging']['level'],
                    handlers=log_handlers)

if args.ldap_auth_only and 'ORAGATE_REDIRECT' not in cfg:
    logging.error('Config variable ORAGATE_REDIRECT is not defined. For ldap-auth-only mode this is mandatory')
    sys.exit(1)


def clean_exit(signame, loop):
    logging.info(f'got signal {signame}, shutting down')
    loop.stop()


async def main():
    loop = asyncio.get_event_loop()
    # catch some termination signals
    try:
        for signame in ('SIGINT', 'SIGTERM', 'SIGHUP', 'SIGABRT', 'SIGALRM'):
            loop.add_signal_handler(getattr(signal, signame), functools.partial(clean_exit, signame, loop))
    except NotImplementedError:
        pass
    # client_connected cb passed as partial because we need some data shared, config for example
    server = await asyncio.start_server(functools.partial(client_connected, cfg=cfg), port=cfg['network']['port'])
    logging.info(f'Start serving on {", ".join([s.getsockname()[0] + ":" + str(s.getsockname()[1]) for s in server.sockets])}')
    async with server:
        try:
            await server.serve_forever()
        finally:
            await server.wait_closed()


# pid lock check
if args.lock_file:
    check_lock(args.lock_file)

try:
    asyncio.run(main())
except KeyboardInterrupt:
    logging.info('Program interrupted by user (KeyboardInterrupt)')
except Exception as e:
    logging.error(e)
finally:
    if args.lock_file:
        remove_lock(args.lock_file)
    logging.info('Server stopped')

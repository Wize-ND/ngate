import argparse
import asyncio
import functools
import logging
import queue
import signal
import sys
from logging.handlers import QueueHandler, QueueListener

import yaml

import db
from oragate import client_connected
from pid_lock import check_lock, remove_lock

# Args section
parser = argparse.ArgumentParser(description='oragate v2')
parser.add_argument('--config_file', '-c', help='config file, YAML format (oragate.yml by default).',
                    default='oragate.yml')
parser.add_argument('--port', help="where to listen incoming requests (overrides config 'network.port' key)")
parser.add_argument('--log_file', help="log file (overrides config 'logging.filename' key)")
parser.add_argument('--lock_file', help="lock file")
parser.add_argument('--ldap_auth_only',
                    help="Mode ldap-auth-only ldap_config and config variable ORAGATE_REDIRECT required).",
                    action='store_true')

args = parser.parse_args()
cfg = yaml.safe_load(open(args.config_file))
cfg['network']['port'] = args.port or cfg['network']['port'] or 1976
cfg['oracle']['dsn'] = db.get_oracle_dsn(cfg)
cfg['ldap_auth_only'] = args.ldap_auth_only
cfg['v'] = '3' or cfg['v']

# logging
log_extra = dict(unique_name='main')
que = queue.Queue(-1)  # no limit on size
queue_handler = QueueHandler(que)
handler = logging.StreamHandler(stream=sys.stdout)
listener = QueueListener(que, handler)
log = logging.getLogger('main')
log.setLevel(cfg['logging']['level'])
log.addHandler(queue_handler)
formatter = logging.Formatter('%(levelname)s %(asctime)-15s - %(threadName)s - %(unique_name)s: %(message)s')
handler.setFormatter(formatter)
listener.start()

if args.ldap_auth_only and 'ORAGATE_REDIRECT' not in cfg:
    log.error('Config variable ORAGATE_REDIRECT is not defined. For ldap-auth-only mode this is mandatory', extra=log_extra)
    sys.exit(1)


def clean_exit(signame, loop):
    log.info(f'got signal {signame}, shutting down', extra=log_extra)
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
    server = await asyncio.start_server(functools.partial(client_connected, cfg=cfg), port=cfg['network']['port'], backlog=0)

    async with server:
        log.info(f'Start serving on {", ".join([s.getsockname()[0] + ":" + str(s.getsockname()[1]) for s in server.sockets])}', extra=log_extra)
        await server.serve_forever()
        await server.wait_closed()
    log.info('Server stopped', extra=log_extra)


# pid lock check
if args.lock_file:
    check_lock(args.lock_file)

try:
    import uvloop

    uvloop.install()
    log.debug('using uvloop')
except ImportError:
    log.debug('uvloop not available, using asyncio loop', extra=log_extra)
    pass

try:
    asyncio.run(main())
except KeyboardInterrupt:
    log.info('Program interrupted by user (KeyboardInterrupt)', extra=log_extra)
except Exception as e:
    log.exception(e, extra=log_extra)
finally:
    if args.lock_file:
        remove_lock(args.lock_file)

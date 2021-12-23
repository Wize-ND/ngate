import argparse
import asyncio
import concurrent.futures
import functools
import logging
import queue
import signal
import sys
from logging.handlers import QueueHandler, QueueListener

import cx_Oracle
import yaml

from oragate import client_connected
from pid_lock import check_lock, remove_lock


def get_oracle_dsn(cfg: dict):
    if 'ora_service_name' in cfg['oracle']:
        return cx_Oracle.makedsn(cfg['oracle']['ora_host'],
                                 cfg['oracle']['ora_port'],
                                 service_name=cfg['oracle']['ora_service_name'])
    elif 'ora_tns_name' in cfg['oracle']:
        return cfg['oracle']['ora_tns_name']
    else:
        return cx_Oracle.makedsn(cfg['oracle']['ora_host'],
                                 cfg['oracle']['ora_port'],
                                 sid=cfg['oracle']['ora_sid'])


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
cfg['oracle']['dsn'] = get_oracle_dsn(cfg)
cfg['ldap_auth_only'] = args.ldap_auth_only
cfg['v'] = '3' or cfg['v']
if 'pool' not in cfg['oracle']:
    cfg['oracle']['pool'] = dict(min=1, max=-1)

# log_handlers = []
# log_file = args.log_file or cfg['logging']['filename'] if 'filename' in cfg['logging'] else None
# if log_file:
#     log_handlers.append(logging.FileHandler(filename=log_file, encoding='utf-8'))
# if 'stdout' in cfg['logging']:
#     log_handlers.append(logging.StreamHandler(stream=sys.stdout))
# logging.basicConfig(format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s: %(message)s',
#                     level=cfg['logging']['level'],
#                     handlers=log_handlers)

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
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=512)
    loop.set_default_executor(executor)
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
print(cfg['oracle']['pool'])
cfg['pool'] = cx_Oracle.SessionPool(encoding='UTF-8',
                                    homogeneous=False,
                                    threaded=True,
                                    min=cfg['oracle']['pool']['min'] if 'min' in cfg['oracle']['pool'] else -1,
                                    max=cfg['oracle']['pool']['max'] if 'max' in cfg['oracle']['pool'] else -1,
                                    getmode=cx_Oracle.SPOOL_ATTRVAL_WAIT,
                                    increment=1,
                                    dsn=cfg['oracle']['dsn'])
print(cfg['pool'].min, cfg['pool'].max, cfg['pool'].opened)
try:
    import uvloop

    uvloop.install()
    log.debug('using uvloop', extra=log_extra)
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

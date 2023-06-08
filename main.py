import logging
import sys
from server import Server

import yaml
from pydantic import ValidationError

from config import Config
from oragate import OragateRequestHandler

if __name__ == '__main__':
    log = logging.getLogger()
    try:
        cfg = Config.parse_obj(yaml.safe_load(open('oragate.yml')))
    except ValidationError as e:
        print(e)
        sys.exit(1)

    logging.addLevelName(19, 'DEBUG_CONN')
    logging.basicConfig(format='%(asctime)s - %(name)s - %(funcName)s - %(levelname)s: %(message)s',
                        stream=sys.stdout,
                        datefmt="%Y-%m-%d %H:%M:%S",
                        level=cfg.logging_level)

    server = Server(('', cfg.port), OragateRequestHandler)
    server.cfg = cfg
    server.max_children = 9999
    with server:
        try:
            log.info(f'Start serving on {":".join(str(i) for i in server.server_address)}')
            server.serve_forever()
        except Exception as e:
            log.exception(e)
            server.shutdown()
    log.info('Server stopped')

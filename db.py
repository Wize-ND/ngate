import logging
import cx_Oracle


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


def default_output(cur: cx_Oracle.Cursor):
    """
    default output of fetch
    :param cur: cx_Oracle.Cursor
    :return: list of dicts or {} if cursor is empty
    """
    columns = [col[0].lower() for col in cur.description]
    cur.rowfactory = lambda *args: dict(zip(columns, args))
    result = [row for row in cur.fetchall()] if cur else {}
    if len(result) == 1:
        result = result[0]
    return result


class OracleConnect(object):
    """
    class to connect to oracle
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.logger = logging.getLogger('Oracle_connection')
        self.conn = cx_Oracle.connect(user=cfg['oracle']['ora_user'],
                                      password=cfg['oracle']['ora_pass'],
                                      threaded=True,
                                      encoding='UTF-8',
                                      dsn=cfg['oracle']['dsn'])

    def __del__(self):
        try:
            self.conn.close()
        except Exception as e:
            self.logger.debug(str(e))

    def execute(self, **kwargs):
        """
        execute a statement (sql or psql)
        :param kwargs:
        :return: default output format of cursor
        """
        query = kwargs['query']
        if 'params' in kwargs:
            params = kwargs['params']
        else:
            params = {}
        with self.conn.cursor() as cur:
            r = cur.execute(query, params)
            if r:
                result = default_output(cur)
            else:
                result = {}
        return result

import datetime
import logging
import cx_Oracle


def default_output(cur: cx_Oracle.Cursor):
    """
    default output of fetch
    :param cur: cx_Oracle.Cursor
    :return: list of dicts or {} if cursor is empty
    """
    rows = [x for x in cur.fetchall()]
    cols = [x[0] for x in cur.description]
    if rows:
        result = [
            dict(zip([col.lower() for col in cols],
                     (value if not isinstance(value, (datetime.datetime, cx_Oracle.LOB)) else str(value) for value in row)))
            for row in rows]
        if len(rows) == 1:
            result = result[0]
    else:
        result = {}
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
                                      encoding='UTF-8',
                                      dsn=cfg['oracle']['dsn'])
        self.conn.module = 'eqm-app-system'

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
        cur = self.conn.cursor()
        try:
            r = cur.execute(query, params)
            self.conn.commit()
            if r:
                result = default_output(cur)
            else:
                result = {}
        finally:
            cur.close()
        return result

    def select_all_from_table(self, table):
        query = f'select * from {table}'
        cursor = self.conn.cursor()
        try:
            r = cursor.execute(query)
            if r:
                result = default_output(cursor)
            else:
                result = {}
        finally:
            cursor.close()
        return result

    def get_table_cols(self, owner: str, table: str):
        query = 'select t.column_name, t.data_type from all_tab_columns t where' \
                f" lower(t.owner) = '{owner.lower()}' and lower(t.table_name) = '{table.lower()}'"
        cursor = self.conn.cursor()
        try:
            r = cursor.execute(query)
            if r:
                result = default_output(cursor)
            else:
                result = {}
        finally:
            cursor.close()
        return result

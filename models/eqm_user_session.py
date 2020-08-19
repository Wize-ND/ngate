import asyncio
import zlib


async def _deflate(data, compress):
    def nested():
        deflated = compress.compress(data)
        deflated += compress.flush(zlib.Z_SYNC_FLUSH)
        return deflated

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, nested)


class EqmUserSession(object):
    """
    user session storage
    """

    def update(self, **kwargs):
        """
        Update __dict__ but only for keys that have been predefined
        (silently ignore others)
        :param kwargs: session vars
        """
        self.__dict__.update((key, value) for key, value in kwargs.items() if key in list(self.__dict__.keys()))

    def __init__(self, reader: asyncio.streams.StreamReader, writer: asyncio.streams.StreamWriter, **kwargs):
        # default vars
        # End of response to successfully processed request.
        self._good_result = '+OK'
        # End of response to unsuccessfully processed request.
        self._bad_result = '-ERROR'
        self.eof = '\r\n'
        self.oragate_cfg = None
        self.user = None
        self.ora_user = None
        self.password = None
        self.app = None
        self.ldap_guid = None
        self.version = None
        self.required_filters = None
        self.desired_filters = None

        # default packet size for results sending in chunks
        self.packet_size = 5000
        self.local_ip = None
        self.peer_ip = None
        self.peer_port = None
        self.app_session_id = None
        self.session_id = None
        self.personal_id = None
        self.db_conn = None
        self.updated = None
        self.reader = reader
        self.writer = writer
        self.ziper = None

        self.update(**kwargs)

        if self.required_filters:
            self.required_filters = self.required_filters.split(',')

    def __del__(self):
        if self.db_conn:
            try:
                self.db_conn.close()
            except Exception as e:
                self.db_conn.debug(str(e))

    def __str__(self):
        return f'user = {self.user}; application = {self.app}; filters = {self.required_filters}; remote host = {self.local_ip}'

    async def send_line(self, line: str):
        """
        send a string
        :param line: string to send
        """
        await self.write_line(line)
        await self.writer.drain()

    async def send_good_result(self, msg=''):
        """
        send ok message
        :param msg: message
        """
        msg = ' ' + msg if msg else msg
        msg = f'{self._good_result}{self.wrap_line(msg)}'.encode()
        if self.ziper:
            msg = await _deflate(msg, self.ziper)
        self.writer.write(msg)
        await self.writer.drain()

    async def send_bad_result(self, msg=''):
        """
        send error message
        :param msg: message
        """
        msg = ' ' + msg if msg else msg
        msg = f'{self._bad_result}{self.wrap_line(msg)}'.encode()
        if self.ziper:
            msg = await _deflate(msg, self.ziper)
        self.writer.write(msg)
        await self.writer.drain()

    def wrap_line(self, msg: str):
        """
        returns msg with eof at end
        :param msg: message
        :return: wrapped msg
        """
        return f'{msg}{self.eof}'

    async def write_line(self, msg: str):
        """
        encode and write line with eof at end
        :param msg: message
        """
        msg = self.wrap_line(msg).encode()
        if self.ziper:
            msg = await _deflate(msg, self.ziper)
        self.writer.write(msg)

    async def write_binary(self, msg: bytes):
        """
        encode and write line with eof at end
        :param msg: message
        """
        if self.ziper:
            msg = await _deflate(msg, self.ziper)
        self.writer.write(msg)

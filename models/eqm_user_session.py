import asyncio
import functools
import zlib
from typing import Optional

import cx_Oracle

special_chars = {chr(n): f'\\{n:02X}' for n in range(0, 32)}


def sync_to_async(f):
    """
    Wrapper function for sync functions to execute them in default(thread) pool asynchronously
    :param f: function
    :return: awaited coroutine(f)
    """

    @functools.wraps(f)
    async def wrapped(*args, **kwargs):
        return await asyncio.get_running_loop().run_in_executor(None, functools.partial(f, *args, **kwargs))

    return wrapped


def special_encode(input_str):
    input_str = input_str.replace('\\', '\\\\').replace('\\', '\\\\')
    for c in special_chars:
        input_str = input_str.replace(c, special_chars[c])
    input_str = input_str.replace(',', '\\\\,')
    return input_str


def special_decode(input_str):
    for c in special_chars:
        input_str = input_str.replace(special_chars[c], c)
    input_str = input_str.replace('\\\\', '\\')
    return input_str.replace('\\,', ',')


async def _deflate(data, compress):
    def deflate():
        deflated = compress.compress(data)
        deflated += compress.flush(zlib.Z_SYNC_FLUSH)
        return deflated

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, deflate)



class EqmUserSession(object):
    """
    user session storage
    """
    __slots__ = ('oragate_cfg', 'user', 'ora_user', 'password', 'app', 'ldap_guid', 'version', 'required_filters',
                 'desired_filters', 'local_ip', 'peer_ip', 'peer_port', 'app_session_id', 'session_id', 'personal_id',
                 'updated', 'reader', 'writer', 'v', 'db_conn', 'ziper')
    # default vars
    # End of response to successfully processed request.
    _good_result = '+OK'
    # End of response to unsuccessfully processed request.
    _bad_result = '-ERROR'
    eof = '\r\n'
    packet_size = 5000
    # buffer size for sending packets in SQL
    buffer_size = 2 ** 17  # 128 KB
    #  amount of time (in milliseconds) that a single round-trip to the database may take before a timeout will occur.
    call_timeout = 60 * 60 * 1000  # 1 hour
    db_conn: Optional[cx_Oracle.Connection]
    oragate_cfg: dict

    def update(self, **kwargs):
        """
        Update attrs but only for attr that have been predefined
        (silently ignore others)
        :param kwargs: session vars
        """
        for k, v in kwargs.items():
            if k in self.__slots__:
                setattr(self, k, special_decode(v) if isinstance(v, str) else v)

    def __init__(self, **kwargs):
        self.db_conn = None
        self.ziper = None
        self.v = kwargs['oragate_cfg']['v']
        self.update(**kwargs)

    def __str__(self):
        return f'user = {self.user}; application = {self.app}; filters = {self.required_filters}; remote host = {self.local_ip}'

    async def apply_filters(self, data: bytes):
        if self.ziper:
            data = await _deflate(data, self.ziper)
        return data

    async def read_data(self, n: int):
        """
        Read up to `n` bytes from the stream, decrypting if enabled
        :param n: num bytes to read
        """
        data = await self.reader.read(n)
        return data

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
        msg = await self.apply_filters(msg)
        self.writer.write(msg)
        await self.writer.drain()

    async def send_bad_result(self, msg=''):
        """
        send error message
        :param msg: message
        """
        msg = ' ' + msg if msg else msg
        msg = f'{self._bad_result}{self.wrap_line(msg)}'.encode()
        msg = await self.apply_filters(msg)
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
        msg = await self.apply_filters(msg)
        self.writer.write(msg)

    async def write_binary(self, msg: bytes):
        """
        encode and write line with eof at end
        :param msg: message
        """
        msg = await self.apply_filters(msg)
        self.writer.write(msg)

    @property
    def good_result(self):
        return self._good_result

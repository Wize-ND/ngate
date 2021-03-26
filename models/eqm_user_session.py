import asyncio
import zlib
from Cryptodome.Cipher import AES

special_chars = {'\n': r'\0A', '\r': r'\0D', '\t': r'\09'}


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
    __slots__ = ('_good_result', '_bad_result', 'eof', 'oragate_cfg', 'user', 'ora_user', 'password', 'app', 'ldap_guid', 'version', 'required_filters',
                 'desired_filters', 'packet_size', 'local_ip', 'peer_ip', 'peer_port', 'app_session_id', 'session_id', 'personal_id', 'db_conn',
                 'updated', 'reader', 'writer', 'ziper', 'encryption_key', 'buffer_size', 'max_life')

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
        # default vars
        # End of response to successfully processed request.
        self._good_result = '+OK'
        # End of response to unsuccessfully processed request.
        self._bad_result = '-ERROR'
        self.eof = '\r\n'
        # default packet size for results sending in chunks
        self.packet_size = 5000
        # buffer size for sending packets in SQL
        self.buffer_size = 2 ** 17  # 128 KB
        self.max_life = 36000  # in seconds (36000 = 10 hours)
        self.ziper = None
        self.encryption_key = None
        self.update(**kwargs)

    def __str__(self):
        return f'user = {self.user}; application = {self.app}; filters = {self.required_filters}; remote host = {self.local_ip}'

    def decrypt_data(self, data: bytes):
        return AES.new(self.encryption_key[0], AES.MODE_CTR, nonce=self.encryption_key[1]).decrypt(data)

    def encrypt_data(self, data: bytes):
        return AES.new(self.encryption_key[0], AES.MODE_CTR, nonce=self.encryption_key[1]).encrypt(data)

    async def apply_filters(self, data: bytes):
        if self.ziper:
            data = await _deflate(data, self.ziper)
        if self.encryption_key:
            data = self.encrypt_data(data)
        return data

    async def read_data(self, n: int):
        """
        Read up to `n` bytes from the stream, decrypting if enabled
        :param n: num bytes to read
        """
        data = await self.reader.read(n)
        if self.encryption_key:
            data = AES.new(self.encryption_key, AES.MODE_CTR).decrypt(data)
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

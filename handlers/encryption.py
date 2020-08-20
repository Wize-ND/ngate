import logging
from models.eqm_user_session import EqmUserSession
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


async def encryption(message: str, session: EqmUserSession):
    log = logging.getLogger('encryption')
    key = get_random_bytes(32)
    session.cipher = AES.new(key, AES.MODE_CTR)
    session.writer.write(key)

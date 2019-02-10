import logging

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

from cr import PaddingOracle, attack

log = logging.getLogger(__name__)

BLOCK_SIZE = 8
KEY = b'abcdefghijklmnopqrstuvwx'
IV = b'abcdefgh'
PLAINTEXT = b'Sir, flag{this_is_the_secret_flag} is the flag you are looking for'


def encrypt(bs):
    cipher = DES3.new(KEY, DES3.MODE_CBC, iv=IV)
    return cipher.encrypt(pad(bs, BLOCK_SIZE))


def decrypt(bs):
    cipher = DES3.new(KEY, DES3.MODE_CBC, iv=IV)
    return unpad(cipher.decrypt(bs), BLOCK_SIZE)


class TripleDESDecryptionPaddingOracle(PaddingOracle):
    def __init__(self, block_size: int, iv: bytes, key: bytes) -> None:
        self._iv = iv
        self._key = key
        super().__init__(block_size)

    # Of course, this oracle is silly since we have the key and iv, but we just use it to determine if the
    # padding is correct or not
    def _oracle_says_padding_correct(self, ciphertext: bytes) -> bool:
        try:
            cipher = DES3.new(self._key, DES3.MODE_CBC, iv=self._iv)
            unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
            return True
        except ValueError:
            return False


def run():
    oracle = TripleDESDecryptionPaddingOracle(BLOCK_SIZE, IV, KEY)
    encrypted_msg = encrypt(PLAINTEXT)
    log.info("Encrypted message: %s", encrypted_msg.hex())
    log.info("Recovering plaintext")
    known_plaintext = attack(encrypted_msg, oracle, BLOCK_SIZE)
    assert known_plaintext.startswith(PLAINTEXT[8:])


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )
    run()

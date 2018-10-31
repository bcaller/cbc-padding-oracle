# CBC padding oracle attack to decrypt all but the first block
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

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



class PaddingOracle:
    def __init__(self, block_size: int) -> None:
        self._block_size = block_size
        self._tries = 0

    def has_correct_padding(self, ciphertext: bytes) -> bool:
        self._tries += 1
        return self._oracle(ciphertext)

    def _oracle(self, ciphertext: bytes) -> bool:
        """Call the oracle and return True if and only if the padding is correct.

        This should e.g. call a remote server and check the error code or decryption timing.
        """
        raise NotImplementedError

    @property
    def tries(self) -> int:
        """Number of times the oracle has been used."""
        return self._tries


class TripleDESDecryptionPaddingOracle(PaddingOracle):
    def __init__(self, block_size: int, iv: bytes, key: bytes) -> None:
        self._iv = iv
        self._key = key
        super().__init__(block_size)

    # Of course, this oracle is silly since we have the key and iv, but we just use it to determine if the
    # padding is correct or not
    def _oracle(self, ciphertext: bytes) -> bool:
        try:
            cipher = DES3.new(self._key, DES3.MODE_CBC, iv=self._iv)
            unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
            return True
        except ValueError:
            return False


class Blocks:
    def __init__(self, data, block_size=BLOCK_SIZE):
        self.data = data
        self.block_size = block_size

    def __getitem__(self, key) -> bytes:
        if isinstance(key, slice):
            start = (key.start * self.block_size) if key.start is not None else None
            end = (key.stop * self.block_size) if key.stop is not None else None
            return self.data[start:end]
        else:
            if key < 0:
                key = len(self) + key
            return self.data[(self.block_size * key):(self.block_size * (key + 1))]

    def __delitem__(self, key) -> None:
        if isinstance(key, slice):
            raise NotImplementedError
        if key < 0:
            key = len(self) + key
        self.data = self[:key] + self[(key + 1):]

    def __len__(self) -> int:
        return len(self.data) // self.block_size


def attack(ciphertext: bytes, oracle: PaddingOracle) -> bytes:
    block_size = BLOCK_SIZE
    cipherblocks = Blocks(ciphertext)
    for i in range(block_size):
        previous_block = bytearray(cipherblocks[-2])
        previous_block[i] = (previous_block[i] + 1) % 256
        last_block = cipherblocks[-1]
        test = bytes(previous_block) + last_block
        if not oracle.has_correct_padding(test):
            padding_length = block_size - i
            break
    else:
        raise Exception("Couldn't find padding")
    print("Padding length:", padding_length)
    known_plaintext = bytearray([padding_length] * padding_length)
    # We know how the last block ends, let's decrypt the whole last block
    known_plaintext = decrypt_final_block(oracle, cipherblocks, known_plaintext)
    del cipherblocks[-1]
    while len(cipherblocks) > 1:
        known_plaintext = decrypt_final_block(oracle, cipherblocks) + known_plaintext
        print(
            "\nDecrypted",
            len(known_plaintext),
            "bytes out of",
            len(ciphertext),
            "after calling the oracle",
            oracle.tries,
            "times",
        )
        print(f"'{known_plaintext.decode('utf-8')}'")
        del cipherblocks[-1]

    return known_plaintext


def decrypt_final_block(oracle: PaddingOracle, cipherblocks: Blocks, known_block_end: bytes=None) -> bytes:
    new_known_plaintext = bytearray() if not known_block_end else known_block_end
    last_block = cipherblocks[-1]
    for attempted_padding_length in range(len(new_known_plaintext) + 1, cipherblocks.block_size + 1):
        previous_block = bytearray(cipherblocks[-2])
        # Alter padding on known parts
        for j in range(attempted_padding_length - 1):
            previous_block[-j-1] = (
                previous_block[-j-1] ^
                new_known_plaintext[-j-1] ^
                attempted_padding_length
            )
        original_value = previous_block[-attempted_padding_length]
        for value in range(256):
            previous_block[-attempted_padding_length] = value
            test = previous_block + last_block
            if oracle.has_correct_padding(test):
                new_known_plaintext.insert(0, value ^ attempted_padding_length ^ original_value)
                break
        else:
            raise Exception("Couldn't decrypt last block")
    return new_known_plaintext


def run():
    oracle = TripleDESDecryptionPaddingOracle(BLOCK_SIZE, IV, KEY)
    encrypted_msg = encrypt(PLAINTEXT)
    print("Encrypted message:", encrypted_msg.hex())
    print("Recovering plaintext")
    attack(encrypted_msg, oracle)


if __name__ == "__main__":
    run()

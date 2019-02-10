import logging

log = logging.getLogger(__name__)


class PaddingOracle:
    """CBC padding oracle to decrypt all but the first block."""
    def __init__(self, block_size: int) -> None:
        self._block_size = block_size
        self._tries = 0

    def has_correct_padding(self, ciphertext: bytes) -> bool:
        self._tries += 1
        return self._oracle_says_padding_correct(ciphertext)

    def _oracle_says_padding_correct(self, ciphertext: bytes) -> bool:
        """Call the oracle and return True if and only if the padding is correct.

        This should e.g. call a remote server and check the error code or decryption timing.
        """
        raise NotImplementedError

    @property
    def tries(self) -> int:
        """Number of times the oracle has been used."""
        return self._tries


class Blocks:
    def __init__(self, data, block_size):
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

def find_padding_length(oracle: PaddingOracle, cipherblocks: Blocks):
    last_block = cipherblocks[-1]
    for i in range(cipherblocks.block_size):
        block_before_last = bytearray(cipherblocks[-2])
        block_before_last[i] = (block_before_last[i] + 1) % 256
        test = bytes(block_before_last) + last_block
        if not oracle.has_correct_padding(test):
            return cipherblocks.block_size - i
    else:
        raise Exception("Couldn't find padding")


def attack(ciphertext: bytes, oracle: PaddingOracle, block_size: int) -> bytes:
    assert len(ciphertext) % block_size == 0, "Ciphertext length not a multiple of expected block size"
    try:
        cipherblocks = Blocks(ciphertext, block_size)
        padding_length = find_padding_length(oracle, cipherblocks)
        log.info("Padding length: %d", padding_length)
        known_plaintext = bytearray([padding_length] * padding_length)
        # We know how the last block ends, let's decrypt the whole last block
        known_plaintext = decrypt_final_block(oracle, cipherblocks, known_plaintext)
        del cipherblocks[-1]
        while len(cipherblocks) > 1:
            known_plaintext = decrypt_final_block(oracle, cipherblocks) + known_plaintext
            log.info(
                "Decrypted %d bytes out of %d after calling the oracle %d times",
                len(known_plaintext),
                len(ciphertext),
                oracle.tries,
            )
            try:
                log.info("'%s'", known_plaintext.decode('utf-8'))
            except UnicodeDecodeError:
                log.info("'%s'", known_plaintext)
            del cipherblocks[-1]

        return known_plaintext
    except:
        log.error("Failed after calling oracle %d times", oracle.tries)
        raise


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

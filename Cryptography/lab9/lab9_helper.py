# This file is provided for you to help with your implementation, DON'T submit this file.
# ONLY submit `lab9.py`

# ------- Question 1 Helpers -------

class Signature(object):
    def __init__(self, z, s, r):
        self.z = z
        self.s = s
        self.r = r
        return
    
    def __repr__(self):
        return "z:{0}\ns:{1}\nr:{2}".format(self.z, self.s, self.r)



# ------- Question 2 Helpers -------

from Cryptodome.Hash import SHA256
from Cryptodome.Hash import HMAC

def hmacsha2(key, message):
    # Note: output is revealed in hex
    return HMAC.new(key, message, SHA256).hexdigest()


# ------- Question 3 Helpers -------

def int_to_hex(integer):
    return integer.to_bytes(((integer.bit_length() + 7) // 8), "big").hex()

# reference: 2048-bit MODP Group (from: https://datatracker.ietf.org/doc/rfc3526/?include_text=1)
p_val = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff'
p_val = int(p_val, 16)

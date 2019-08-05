#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 6 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import lab6_helper, binascii, os
from Crypto.Cipher import AES
from Cryptodome.Hash import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def q1_encrypt_mac(enc_key, hmac_key, blob):
    """Question 1: Encrypt-then-MAC

    In Lecture 12, we discussed the difference in behavior between MAC-then-Encrypt
    and Encrypt-then-MAC. We concluded that the latter was the better way to
    protect + authenticate data in transit because the former was plagued by the
    fact that the receiver might try to decrypt data before verifying that it
    comes from the correct source.

    The scenario:
        In this problem, you will take on the role of Bob. Assume that Alice sends
        you messages that follow the Encrypt-then-MAC paradigm.
        That is: Alice first encrypts her messages using AES in CBC mode with
        PKCS#7 padding, and then she MACs the message using HMAC-SHA1.

        You (Bob) possess both the `aes-key` and the `hmac-key`.


    Your Task:
        Construct the verify-then-decrypt routine for Bob to use in order to
        validate and then read messages sent by Alice. You should parse the blob
        sent by Alice in the following way:

        the first 16 bytes are the IV for CBC mode, the last 20 bytes are the
        HMAC-SHA1 tag, and everything in the middle is the CBC ciphertext
        corresponding to the padded message.

        Your function should return the correct message if it was properly
        Encrypted-then-MAC'd, or it should output the string 'ERROR' (without the quotes)
        if there is an issue. (You may assume that Alice will never send you the
        string ERROR intentionally.)

    Args:
        enc_key     (str):  16-bytes hex-encoded key to be used for AES
        hmac_key    (str):  20-bytes hex-encoded key to be used for HMAC
        blob  (str):  arbitrary-length hex-encoded data (ciphertext)
    Output:
        ret         (str):  ASCII-encoded, unpadded message (or 'ERROR' if there
                            is a problem with the input blob invalid)
    Test vectors:
        assert(q1_encrypt_mac(  '7369787465656e2062797465206b6579',
                                '7477656e74792062797465206c6f6e67206b6579',
                                ('00000000000000000000000000000000a70c430ebf'
                                '35441874ac9f758c59ee10e931378c49507b45b278'
                                'f922db372a682e13bf25')) == 'valid message')

        assert(q1_encrypt_mac(  '7369787465656e2062797465206b6579',
                                '7477656e74792062797465206c6f6e67206b6579',
                                ('00000000000000000000000000000000a70c430ebf'
                                '35441874ac9f758c59ee10e931378c49507b45b278'
                                'f922db372a682e13bf34')) == 'ERROR') #1-byte change
    """

    # TODO: Complete me!
    def remove_pkcs_pad(padded_msg, block_size):
        """Removes PKCS#7 padding if it exists and returns the un-padded message
        Args:
            padded_msg  (bytes/bytearray)

        ret(bytes/bytearray): un-padded message if the padding is valid, None otherwise
        """
        padded_msg_len = len(padded_msg)

        if padded_msg_len == 0:
            return "ERROR"

        # Checks if the input is not a multiple of the block length
        if (padded_msg_len % block_size):
            return "ERROR"

        # Last byte has the value
        pad_len = padded_msg[-1]

        # padding value is greater than the total message length
        if pad_len > padded_msg_len:
            return "ERROR"

        # Where the padding starts on input message
        pad_start = padded_msg_len - pad_len

        # Check the ending values for the correct pad value
        for char in padded_msg[padded_msg_len:pad_start - 1:-1]:
            if char != pad_len:
                return "ERROR"

        # remove the padding and return the message
        return padded_msg[:pad_start]


    blob_hex = binascii.unhexlify(blob)
    enc_key_hex = binascii.unhexlify(enc_key)
    hmac_key_hex = binascii.unhexlify(hmac_key)
    iv = bytes.fromhex(blob[:32])
    tag = bytes.fromhex(blob[-40:])
    message = bytes.fromhex(blob[32:-40])
    ciphertext = blob[:-40]
    test = lab6_helper.hmacsha1(hmac_key_hex, bytes.fromhex(ciphertext))
    if bytes.fromhex(test) == tag:
        cipher = AES.new(enc_key_hex, AES.MODE_CBC, iv)
        test2 = cipher.decrypt(bytes.fromhex(ciphertext[32:]))
        ret = remove_pkcs_pad(test2, 16)
        if ret == "ERROR":
            return "ERROR"
        else:
            return ret.decode('ascii')
    else:
        return "ERROR"


# print(q1_encrypt_mac('7369787465656e2062797465206b6579',
#                                 '7477656e74792062797465206c6f6e67206b6579',
#                                 ('00000000000000000000000000000000a70c430ebf'
#                                 '35441874ac9f758c59ee10e931378c49507b45b278'
#                                 'f922db372a682e13bf25')))
# #print("----------------")
# print(q1_encrypt_mac('7369787465656e2062797465206b6579',
#                                 '7477656e74792062797465206c6f6e67206b6579',
#                                 ('00000000000000000000000000000000a70c430ebf'
#                                 '35441874ac9f758c59ee10e931378c49507b45b278'
#                                 'f922db372a682e13bf34')))

#print(q1_encrypt_mac("a7632c51f3f9f72e0063e6e39b233606", "859e9193cddf39f3e5b472178c033312", "785b503cc8d252cbd5803a7c50a1838f88e24c177055e6e6bc4f57baf4941261d66bccfab212e5cd4a8001c2a97dfa4d61b2a9c427cd9f9cda27e72f27f241bf48e911308b4acd3a93ecb5820fabe00ccbbb13d09c552702d97ea92b759485f9f1eaa150"))


def q2_siv_mode_enc(enc_key, mac_key, plaintext, associated_data):
    """Question 2 (part 1): Synthetic Initialization Vector (SIV) Authenticated Encryption

    Your Task:
        Your function should implement the SIV mode for authenticated encryption
        as illustrated in lecture 13. For this implementation, you would have to
        use the AES block cipher in CTR mode, along with CMAC as a MAC.
    Args:
        enc_key         (str):  16-bytes hex-encoded key to be used for AES
        mac_key         (str):  16-bytes hex-encoded key to be used for CMAC
        plaintext       (str):  arbitrary-length ASCII encoded plaintext
        associated_data (str):  arbitrary-length hex-encoded data to be
                                authenticated, but not encrypted
    Output:
        ret             (str):  hex-encoded, ciphertext formatted as
                                    tag + ciphertext (as shown in Lecture slides)
    Test vectors:
        assert(q2_siv_mode_enc( enc_key="7f7e7d7c7b7a79787776757473727170",
                        mac_key="404142434445464748494a4b4c4d4e4f",
                        plaintext="this is some plaintext to encrypt using SIV-AES",
                        associated_data = "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
                ) == "2550eb1783787e5f2d4e56fba6dff0a7df554c297854c8c4e4833435e66989314b6b2791862c7d11498c2ef034bfbb63808c73bc5ea23e64cb58a8e1a5775a")
    Note:

        Also Feel free to use componenets from the Cryptodome/cryptography libraries
        to build this function (ex. `from Crypto.Hash import CMAC`). That being
        said, you should not use the SIV mode provided by any library, you should
        combine the building blocks to implement the SIV mode on your own.

        When using the tag as a nonce for the CTR mode, some CTR implementations
        would not allow the nonce to be equal to the block_size (for example,
        the `Cryptodome.Cipher` class with throw an error when using a nonce
        of size > block_size - 1), so I recommend using the CTR mode provided by
        the library `cryptography` instead
        (e.g `from cryptography.hazmat.primitives.ciphers import Cipher`).

        Also note that for this implementation, there's no need to clear any bits
        of the tag before using it as a nonce. You can assume that the number of
        blocks we would test against would not overflow the counter bits.
    """

    # TODO: Complete me!
    # print(enc_key)
    # print(mac_key)
    # print(plaintext)
    # print(associated_data)
    plaintext_hex = binascii.hexlify(plaintext.encode('ascii'))
    pre_mac = associated_data + plaintext_hex.decode('ascii')
    # print(bytes.fromhex(mac_key))
    # DO CMAC
    cobj = CMAC.new(bytes.fromhex(mac_key), ciphermod=AES)
    cobj.update(bytes.fromhex(pre_mac))
    # print("---")
    # ENCRYPT
    cipher = Cipher(algorithms.AES(bytes.fromhex(enc_key)), modes.CTR(bytes.fromhex(cobj.hexdigest())), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes.fromhex(plaintext_hex.decode('ascii')))
    ciphertext = binascii.hexlify(ct).decode('ascii')
    return cobj.hexdigest() + ciphertext

# print(q2_siv_mode_enc("7f7e7d7c7b7a79787776757473727170",
#                         "404142434445464748494a4b4c4d4e4f",
#                         "this is some plaintext to encrypt using SIV-AES",
#                         "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"))

# print('----')

def q2_siv_mode_dec(enc_key, mac_key, ciphertext, associated_data):
    """Question 2 (part 2): Synthetic Initialization Vector (SIV) Authenticated Encryption

    Your Task:
        Similar to the first part of this question, your function should decrypt
        the output produced by the function in the first part and return the
        plaintext if the tag is valid, and return ERROR otherwise.
    Args:
        enc_key         (str):  16-bytes hex-encoded key to be used for AES
        mac_key         (str):  16-bytes hex-encoded key to be used for CMAC
        ciphertext      (str):  arbitrary-length hec-encoded ciphertext (same format
                                as the output of q2_siv_mode_enc)
        associated_data (str):  arbitrary-length hex-encoded data to be
                                authenticated, but not encrypted
    Output:
        ret             (str):  ASCII-encoded, plaintext (or 'ERROR')
    Test vectors:
        Use the same test case provided in part 1 of this question.
    """

    # TODO: Complete me!
    # print(enc_key)
    # print(mac_key)
    # print(ciphertext)
    # print(associated_data)
    ciphertext_hex = binascii.hexlify(ciphertext.encode('ascii'))
    # print(ciphertext_hex)
    # DECRYPT
    tag = ciphertext[:32]
    ct = ciphertext[32:]
    cipher = Cipher(algorithms.AES(bytes.fromhex(enc_key)), modes.CTR(bytes.fromhex(tag)), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = binascii.unhexlify(ct.encode('ascii'))
    # print("pt", pt)
    plaintext = decryptor.update(bytes.fromhex(ct))
    # print("plaintext", plaintext)
    try:
        plaintext = plaintext.decode('ascii')
        return plaintext
    except:
        return "ERROR"



    # if :#TODO TRUE
    #     return plaintext
    # else:
    #     return "ERROR"


    # print(enc_key)
    # print(mac_key)
    # print(plaintext)
    # print(associated_data)
    # plaintext_hex = binascii.hexlify(plaintext.encode('ascii'))
    # print(plaintext_hex.decode('ascii'))
    # pre_mac = associated_data + plaintext_hex.decode('ascii')
    # print("premac", pre_mac)
    # # print(bytes.fromhex(mac_key))
    # print(bytes.fromhex(plaintext_hex.decode('ascii')))
    # # DO CMAC
    # cobj = CMAC.new(bytes.fromhex(mac_key), ciphermod=AES)
    # cobj.update(bytes.fromhex(pre_mac))
    # print(cobj.hexdigest())


# print(q2_siv_mode_dec("7f7e7d7c7b7a79787776757473727170",
#                         "404142434445464748494a4b4c4d4e4f",
#                         "2550eb1783787e5f2d4e56fba6dff0a7df554c297854c8c4e4833435e66989314b6b2791862c7d11498c2ef034bfbb63808c73bc5ea23e64cb58a8e1a5775a",
#                         "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"))

def q3_block_cipher_timing_attack(leaky_encipher=lab6_helper.leaky_encipher_example):
    """Question 3: Collision timing attack on AES

    Your Task:
        In this function, we'll perform a first round timing attack on AES. This
        attack is different from the one in the last lab since you will be trying
        to extract the enciphering key used by only observing the number of colliding
        bytes by timing the cache when performing the S-Box substitutions on the
        first round of AES.

        The routine 'leaky_encipher' can be used to query the number of distinct
        bytes of the internal state after the first round of substitutions that
        AES performs, the routine also returns the final ciphertext produced by
        AES on the given plaintext (using a secret key).

        For example (using 4-bytes as an example, the routine handles
            16-bytes state values), this is how `leaky_encipher` would work:
            internal_state="01 02 03 04" -> 4
            internal_state="01 01 03 04" -> 3
            internal_state="01 01 01 04" -> 2
            internal_state="01 01 01 01" -> 1
    Args:
        leaky_encipher  (func)  : performs an AES encipher on a 16-bytes input
                                    (check lab6_helper.leaky_encipher_example
                                        for more details)
    Output:
        ret             (str)   : hex-encoded 16-bytes string that represents
                                    the secret key used in leaky_encipher.
    How to verify your answer:
        assert(q3_block_cipher_timing_attack() == lab6_helper.TEST_KEY)
    """

    # TODO: Complete me
    array = []
    for i in range(1, 16):
        array.append(find_collision(i, leaky_encipher))

    # brute force for all the possible 256 values of k0
    for i in range(256):
        key = [i] + get_keys(i, array)
        key = bytes(key)
        encipher = AES.new(key, AES.MODE_ECB)
        random_text = os.urandom(16)
        z1 = binascii.hexlify(encipher.encrypt(random_text))
        z2 = binascii.hexlify(leaky_encipher(random_text)[1])

        if z1 == z2:
            return binascii.hexlify(key).decode()


# for a specific k0, get k1,k2,k3...k15
def get_keys(k0, xores):
    keys = []
    for i in range(0, len(xores)):
        keys.append(k0 ^ xores[i])
    return keys


# given an array with values, find the index of the minimum value
def min_index(arr):
    return arr.index(min(arr))


# finds collision between x_0 and x_index
def find_collision(index, leaky_encipher):
    assert (index > 0 and index < 16)
    # holds the score for each value of i tested, it's more like the sum
    average = []
    for i in range(0, 256):
        sum_val = 0
        for _ in range(100):
            # generate a random string with the first byte being fixed to 00
            # the byte at index is fixed to i, all the other bytes are random
            first_byte = binascii.unhexlify("00") + \
                         os.urandom(index - 1) + binascii.unhexlify('{:02x}'.format(i))
            plaintext = first_byte + os.urandom(16 - index - 1)
            a, _ = leaky_encipher(plaintext)
            sum_val += a
        average.append(sum_val)
    return min_index(average)

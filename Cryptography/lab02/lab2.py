#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 2 ##################################################################

"""
List you collaborators here:
                                party one
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out, and an example test case is provided for your convenience.
"""

# Feel free to use either of `Cryptodome` or `cryptography` below

from Cryptodome.Cipher import AES
import binascii


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from Cryptodome.Util.strxor import strxor


def aes_encipher(key, plaintext):
    """Performs an AES encipher on the input "plaintext" using the default ECB mode.
    Args:
        key (str): hex-encoded string of length 16-bytes (default AES block input size).
        plaintext (str): hex-encoded string of length 16 bytes (default AES block input size).

    Returns:
        str: The ciphertext output as a hex-encoded string

    Note:
        One thing you'll find in cryptography is that tests are your friend. Granted, unit tests are important in all of software
        development, but cryptography has two properties that make testing even more important still:
            -   The output of any cryptosystem is supposed to look random. So spot-checking the output won't help you to distinguish
                whether it was implemented correctly or not.
            -   It is essential that your implementation interoperate with everybody else's implementation of the same cipher,
                so that Alice and Bob can produce the same results when one of them uses your code and the other uses someone else's code.
                Ergo, it is important that everybody follows the cipher designers' spec exactly, even down to low-level details like whether strings
                follow big or little endianness. (Note: if you don't know what `endianness' means, just ignore that last comment.)
        For this question, here are some test vectors you can use. I provide an AES-128 key (16 bytes long) and a plaintext (16 bytes long) along with
        the associated 16-byte ciphertext for the plaintext.

    Test vectors:
        aes_encipher(key = "00000000000000000000000000000000", plaintext = "f34481ec3cc627bacd5dc3fb08f273e6") == "0336763e966d92595a567cc9ce537f5e"
        aes_encipher(key = "00000000000000000000000000000000", plaintext = "9798c4640bad75c7c3227db910174e72") == "a9a1631bf4996954ebc093957b234589"
        aes_encipher(key = "00000000000000000000000000000000", plaintext = "96ab5c2ff612d9dfaae8c31f30c42168") == "ff4f8391a6a40ca5b25d23bedd44a597"
    """

    # TODO: Complete me!
    key = binascii.unhexlify(key)
    plaintext = binascii.unhexlify(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.encrypt(plaintext)
    return binascii.hexlify(message).decode('ascii')
    pass

print(aes_encipher("00000000000000000000000000000000","f34481ec3cc627bacd5dc3fb08f273e6"))


def find_key(plaintext, ciphertext):
    """Given a plaintext and a ciphertext, find the 16-bytes key that was used under AES (ECB mode, just like in `aes_encipher`) to produce the given ciphertext.

    Args:
        plaintext (str): hex-encoded string of length 16 bytes.
        ciphertext (str): hex-encoded string of length 16 bytes.

    Returns:
        str: hex-encoded 16-bytes key used to produce 'ciphertext' given 'plaintext' under AES (ECB-mode)

    Note:
        Keep in mind that AES keys are 128-bits (16 bytes), and you should assume for this question that the first **108-bits** of the AES key are all zeros.

    Hint:
        Use brute-force!

    Examples:
        find_key(plaintext = "f34481ec3cc627bacd5dc3fb08f273e6", ciphertext = "3ed20de893c03d47c6d24f09cb8a7fd2") ==  "00000000000000000000000000000001"
        find_key(plaintext = "f34481ec3cc627bacd5dc3fb08f273e6", ciphertext = "ac021ba807067a148456ffb140cd485f") ==  "0000000000000000000000000000d7f6"
        find_key(plaintext = "f34481ec3cc627bacd5dc3fb08f273e6", ciphertext = "78e7e91df1a6792fce896e3e1925461d") ==  "0000000000000000000000000001dae9"
    """

    # TODO: Complete me!
    key = "00000000000000000000000000000000"
    for count in range(2**20):
        keytest = binascii.unhexlify(key)
        plaintexttest = binascii.unhexlify(plaintext)
        cipher = AES.new(keytest, AES.MODE_ECB)
        message = cipher.encrypt(plaintexttest)
        ciphered = binascii.hexlify(message).decode('ascii')
        if ciphered == ciphertext:
            return key
        else:
            key = int(key, 16) + 1
            key = hex(key)
            key = '0' * (34 - len(key)) + key[2:]
    pass

# from lab1 import *                                # IMPORT FUNCTIONS FROM LAB1
def two_time_pad():
    """A one-time pad simply involves the xor of a message with a key to produce a ciphertext: c = m ^ k.
        It is essential that the key be as long as the message, or in other words that the key not be repeated for two distinct message blocks.

    Your task:
        In this problem you will break a cipher when the one-time pad is re-used.
        c_1 = 3801025f45561a49131a1e180702
        c_2 = 07010051455001060e551c571106
        These are two hex-encoded ciphertexts that were formed by applying a â€œone-time padâ€ to two different messages with
        the same key. Find the two corresponding messages m_1 and m_2.

    Okay, to make your search simpler, let me lay out a few ground rules. First, every character in the text is either
    a lowercase letter or a space, aside from perhaps the first character in the first message which might be capitalized.
    As a consequence, no punctuation appears in the messages. Second, the messages consist of English words in ASCII.
    Finally, all of the words within each message is guaranteed to come from the set of the 100 most
    common English words: https://en.wikipedia.org/wiki/Most_common_words_in_English.

    Returns:
        Output the concatenation of strings m_1 and m_2. (Don't worry if words get smashed together as a result.)
    """

    # TODO: Complete me!
    # c_1 = "3801025f45561a49131a1e180702"              # GIVEN FROM QUESTION
    # c_2 = "07010051455001060e551c571106"              # GIVEN FROM QUESTION
    # c = hex(int(c_1, 16) ^ int(c_2, 16))[2:]          # XOR OF ORIGINAL MESSAGE
    # crib = " "                                        # WORDS TO BE TESTED: (SPACE), YOU, WORK, GOOD, SOME (ALL LOWER CASE)
    # crib = string_to_hexstring(crib)                  # IMPORTING LAB1.PY STRING_TO_HEXSTRING
    # for i in range(len(c) - len(crib) + 1):           # MAKE A LOOP TO XOR IN EVERY BYTE, CHECKING IF THE OUTPUT IS A WORD IN THE TABLE
    #     if i % 2 == 0:                                # EACH LETTER IS 1/2 BYTE
    #         print("XOR String   : \"", hexstring_to_string(hex(int(c[i:i+len(crib)], 16) ^ int(crib, 16))[2:]), "\"")           # m1 = c1 ^ c^2 ^ m2, CHECK IF A WORD EXISTS
    #         print("Hex-String is: \"", hex(int(c[i:i+len(crib)], 16) ^ int(crib, 16))[2:], "\"")                                # PRINT HEX-STRING
    #         print("Byte Range is: ", i/2 + 1, "-", (i+len(crib))/2)                                                             # PRINT BYTE RANGE
    #         print("----------------------------")
    # FIRST, I INPUT SPACE TO THE VARIABLE CRIB, AND SEE WHICH BYTE RANGE HAS WHICH THE SAME CHAR, OR WHICH BYTE RANGE OUTPUTS A LETTER THAT FITS THE DESCRIPTION
    # THEN, FROM THE POSSIBILITIES, I CHECK WIKIPEDIA AND TRY TO FIND WORDS THAT CONTAIN AN 'O', AND SEE WHAT THEY OUTPUT.
    # BY REPEATING THIS METHOD, I SEARCH FOR THE WORD YOU, WHICH GIVES ME 'D W', AND THEN SEARCH FOR WORDS THAT START WITH 'W'
    # BY PUTTING 'WORK' IN CRIB, I GET 'U DO' AS AN OUTPUT, AND KEEP ON DOING THIS TO FIND ALL BYTES FROM BYTE RANGE 5-14.
    # NOW I NEED TO FIND THE FIRST FOUR CHARACTERS IN THE MESSAGE.
    # BY CREATING A LIST OF ALL FOUR LETTER WORDS, AND PUTTING IT INTO CRIB, I ENDED UP WITH 'SOME' TO OUTPUT 'LOOK', WHICH THEN COMPLETES THE MESSAGE DECIPHERING
    return "Look at you dosome good work"


# This file is provided for you to help with your implementation, DON'T submit this file.
# ONLY submit `lab5.py`

# ------- Problem 1 Helper functions -------

from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA as SHA1
from Cryptodome.Util.strxor import strxor
from binascii import unhexlify

from aeskeyexp import aes128_lastroundkey

TEST_KEY = "0" * 16 # NOTE: Just as an example, a random key would be used to test your code

def hmacsha1(key, message):
    return HMAC.new(bytes.fromhex(key), message.encode('ascii'), SHA1).hexdigest() # Note: output is revealed in hex

def hmacsha1test(): # Using test cases taken from RFC 2202 (https://tools.ietf.org/html/rfc2202)
    key1 = unhexlify("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    msg1 = "Hi There"
    mac1 = "b617318655057264e28bc0b6fb378c8ef146be00"
    assert(hmacsha1(key1, msg1) == mac1)
    key2 = "Jefe"
    msg2 = "what do ya want for nothing?"
    mac2 = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    assert(hmacsha1(key2, msg2) == mac2)
    key3 = unhexlify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    msg3 = unhexlify("dd") * 50
    mac3 = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    assert(hmacsha1(key3, msg3) == mac3)
    print("hmacsha1test successful")

def leaky_hmac_verify_example(message, claimed_tag):
    key = TEST_KEY # NOTE: Just as an example, a random key would be used to test your code
    # Assume that the tag is well-formed, so it's even possible to be the hex encoding of an HMAC-SHA1 output (which would be 20 bytes long)
    assert(len(claimed_tag) == 40)

    # Test validity of the claimed tag
    valid_tag = hmacsha1(key, message)                         # This is what the tag should be, in hex
    is_valid_tag = (claimed_tag == valid_tag)

    if(is_valid_tag):                                          # The tag is valid, so the "first difference" is after the end of the string
        return [is_valid_tag, 4 * len(valid_tag)]
    else:                                                      # The tag is invalid, and we must find the location of the first difference
        diff = strxor(unhexlify(claimed_tag),                  # To do so, we take the xor between the (raw) tag and valid_tag
                              unhexlify(valid_tag)).hex()      # and then find the first non-zero bit in this string (which is easier to do when hexlify'd)
        diffstrip = diff.lstrip("0")                           # Remove all of the leading hex-0 characters
        first_diff_location = 4 * (len(diff) - len(diffstrip)) # Each leading hex-0 denotes four bits that are identical between the two strings
        char = diffstrip[0]                                    # This character is guaranteed to be a non-zero hex character
        leading_bits = {'1' : 3,                               # This dictionary provides the # of leading zero bits for each non-zero hex character
                        '2' : 2,
                        '3' : 2,
                        '4' : 1,
                        '5' : 1,
                        '6' : 1,
                        '7' : 1,
                        '8' : 0,
                        '9' : 0,
                        'a' : 0,
                        'b' : 0,
                        'c' : 0,
                        'd' : 0,
                        'e' : 0,
                        'f' : 0,}
        first_diff_location += leading_bits[char]
        return [is_valid_tag, first_diff_location]             # Return whether the tag is correct *and* the location of the first difference


# ------- Problem 2 and 3 Helper functions -------


from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

# AES Inverse S-box, reproduced from https://anh.cs.luc.edu/331/code/aes.py
def Sinv(byte_index):
    _Sinv = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
    return _Sinv[byte_index]


def leaky_encipher_example(A):
    """performs an AES encipher on the input 16-bytes input `file_bytes`
    
    Args:
        A   (bytes)         : 16-bytes input to be passed to AES for enciphering
    
    Output:
        ret (bytes, set)    : tuple with the actual ciphertext and a Python set stating which cachelines 
                                    are accessed during the final round's SubBytes operation.
    """
    
    key = TEST_KEY # NOTE: Just as an example, a random key would be used to test your code
    # Let me denote the state in AES as follows:
    # A = input to AES
    # Z = enciphering of A (aka, result after applying all 10 rounds)
    # Y = value just before the final AddRoundKey
    # X = value at the beginning of the 10th round, before ShiftRows and SubBytes as well (remember: the final round lacks MixColumns)
    
    # So the final round of AES looks like this:
    # X -> [SubBytes] -> [ShiftRows] -> Y -> [AddRoundKey, aka strxor with lastroundkey] -> Z
    
    # First, perform all 10 rounds of AES
    assert(len(A) == 16)
    permutation = AES.new(key.encode('ascii'), AES.MODE_ECB)
    Z = permutation.encrypt(A)               # This is the desired output! Now we just have to simulate the cache lines...
    
    # Now go back one round of AES, from the end back to the beginning. We begin with AddRoundKey, which is its own inverse.
    lastroundkey = aes128_lastroundkey(key)  # This is the key used in the final xor step of AES. You need the aeskeyexp helper file for this.
    Yvec = strxor(Z, lastroundkey)              # xor is its own inverse
    
    # ShiftRows is irrelevant here because it merely permutes the order of bytes, and we won't care about that when we output a set.
    # So it remains to perform an inverse SubBytes operation.
    X = frozenset(map(Sinv, Yvec)) # Apply Sinv to each byte of the state, and form the *set* of resulting values
    
    # Return both the ciphertext and the set of bytes at the start of the 10th round
    return [Z, X]

def less_leaky_encipher_example(A):
    key = TEST_KEY # NOTE: Just as an example, a random key would be used to test your code

    # I use the variables A, X, Y, and Z here just as in the previous routine
    
    # Let's compute Yvec just as we did before.
    assert(len(A) == 16)
    permutation = AES.new(key.encode('ascii'), AES.MODE_ECB)
    Z = permutation.encrypt(A)
    lastroundkey = aes128_lastroundkey(key)
    Yvec = strxor(Z, lastroundkey)
    # Now we invert the SubBytes operation, but only store the set of the upper 4 bits of the result
    Xvec = map(Sinv, Yvec)                       # This is the *list* of full bytes at the start of the 10th round
    X = frozenset( map(lambda x: x >> 4, Xvec) ) # And now we form the *set* of values with the lower 4 bits truncated
    # Return the enciphering of A together with the *set* of cache lines accessed in round 10
    return [Z, X]

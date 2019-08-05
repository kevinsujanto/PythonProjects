#!/usr/bin/env python3
# -*- coding: utf-8 -*-


################################################################## LAB 3 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out, and an example test case is provided for your convenience.
"""

from Cryptodome.Util.strxor import strxor

from sample_cipher import Sample_Cipher
import binascii

def q1_mitm_cipher(message, ciphertext, cipher=Sample_Cipher):
    """Question 1: Meet in the middle attack

    Args:
        message     (str):      hex-encoded string of length 8 bits (1 byte).
        ciphertext  (str):      hex-encoded string of length 8 bits (1 byte).
        cipher      (Cipher):   Cipher class (check `sample_cipher.py`) that provides the following methods to help you solve the problem:
                                    +   cipher.TOY(message, key)
                                    +   cipher.TOY_inv(ciphertext, key)
                                    +   cipher.sub_word(word)       <-- optional to solve this problem
                                    +   cipher.inv_sub_word(word)   <-- optional to solve this problem
    Description:
        This problem involves cryptanalysis of a simple cipher I'll call TOY. It operates on a 8-bit input "message" and produces a 8-bit output "ciphertext". 
        The cipher involves 2 steps: xor with a 8-bit key k_0 and the application of a non-linear S-box (found in "cipher"), then another xor with the same 8-bit 
        key k_0.

        TOY is really weak for a variety of reasons, most of which I'll ask you to ignore for this problem. Let's strengthen it slightly by iterating 
        it twice to produce a cipher I call 2TOY.

                      k_0                         k_0
                       |                           |
                       |        +-------------+    |
                       |        |             |    |
                       v        |             |    v
        message +------⊕------->    S-Box    +-----⊕-------> ciphertext
                                |             |
                                |             |
                                +-------------+
                                Figure 1: Cipher TOY 
        

                      k_0                  k_1                      k_0
                       |                    |                        |
                       |                    |                        |
                       |    +---------+     |        +---------+     |
                       v    |         |     v        |         |     v
        message  +-----⊕--->  S-Box  +------⊕------->  S-Box  +------⊕-----> ciphertext
                            |         |              |         |
                            +---------+              +---------+
                            Figure 2: Cipher 2TOY 
        
        As before, 2TOY receives a 8-bit input and returns a 8-bit output. Unlike TOY though, this cipher has an 16-bit key $(k_0, k_1)$.

    Your Task:
        Complete this function that executes a "meet-in-the-middle" attack to find the set of keys consistent with the given (message, ciphertext) pair 
        quicker than a 16-bit brute-force search would. This function should take advantage of the structure of 2TOY as two applications of TOY. 
                
        As the name of the attack suggests, the best path forward here is to compute 2TOY from the outside to the middle. In more detail: 
        let the variable 'w' denote the value on the wire in between the first S-box and the xor-with-k_1 steps. Your code should 
        compute 'w' using one call to TOY and another (independent) call to TOY_inverse.
        
        
        Your code should leverage this fact to compute the set of keys consistent with a given (message, ciphertext). That is, your code should 
        run in 2*2^n time rather than 2^{2n} time, where n is the length of the key of TOY (n = 8, in our case). The downside is that your 
        code **might** also require 2*2^n intermediate state, whereas a naive brute-force attack would not.
        
        This problem is an example of a time-memory tradeoff in cryptanalysis, and it's the reason why DES was strengthened by moving to 3DES
        rather than 2DES (which would only add 1 bit of security to DES).

    Your output:
        Find all keys (k_0, k_1), of length 8-bits each (so 16-bit in total), that would output `ciphertext` when `message` is passed to `2TOY`. 
        
        Output the keys as hex-formatted lowercase strings, and concatenate them together in **increasing** order.
    
    NOTE:
        To get full-credit on this question, you must follow the following requirements:
            + Only use `cipher.TOY(message, key)` and/or `cipher.TOY_inv(ciphertext, key)` from `cipher`
                + Using anything else in `cipher` (e.g. directly accessing the `s-box`) is not required to solve this problem.
            + The runtime of your solution should not exceed 2*2^n (n=8 in this case)
                + This will be measured by how many calls you make to the methods in `cipher`
    Test vectors:
        sha256( q1_mitm_cipher("aa", "bb", Sample_Cipher()) ) == "72c1b83cc1245b4d570f78cd3ab7060898f302b095a834e10d5f3e988da83e7d"
        sha256( q1_mitm_cipher("bb", "aa", Sample_Cipher()) ) == "99ba39b2496461b9a5d153427411e0bc394700685cdaf0b99d23ef8eb9fa9add"
    """

    # TODO: Complete me!
    test = ""
    for key0 in range(2**8):
        if key0 < 16:
            key0 = "0" + hex(key0)[2:]
        else:
            key0 = hex(key0)[2:]
        w1 = cipher.TOY(message, key0)
        w2 = cipher.TOY_inv(ciphertext, key0)
        key1 = strxor(bytes.fromhex(w1), bytes.fromhex(w2))
        key1 = binascii.hexlify(key1)
        key1 = hex(int(key1, 16))[2:]
        if len(key1) < 2:
            key1 = "0" + key1
        test = test + str(key0) + str(key1)
    return test

def q2_cbc_mac(key, message, cipher=Sample_Cipher):
    """Question 2
        Args:
            key     (str):      ascii input string (1-byte long)
            message (str):      ascii input string with an arbitrary length
            cipher  (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to the TOY cipher
                                    +   cipher.TOY(message, key)
        Your task:
            Implement CBC-MAC mode on top of the TOY cipher (from question 1). Using the TOY cipher will result in a 
            tag of length 1-byte, such a short tag limits the security guarantees, but we won't focus on that in this question.
        
        Your Output:
            Compute and return the 1-byte message tag as a hex-encoded string
        
        Test vectors:
            q2_cbc_mac("k", "This is a test message!", Sample_Cipher()) == "1f"
            q2_cbc_mac("a", "print(\"CBC-MAC is a very strong hash function!\")", Sample_Cipher()) == "a6"
            q2_cbc_mac("m", "short_msg", Sample_Cipher()) == "12"
    """

    # TODO: Complete me!
    key = hex(ord(key))[2:]
    for i in range(len(message)):
        substring = message[i:i+1]
        input = hex(ord(substring))[2:]
        # XOR
        iv = "00"
        if i > 0:
            iv = post_encrpyt
        post_XOR = strxor(bytes.fromhex(iv), bytes.fromhex(input))
        post_XOR = hex(int(binascii.hexlify(post_XOR), 16))[2:]
        if len(post_XOR) == 1:
            post_XOR = "0" + post_XOR
        # ENCRYPT
        post_encrpyt = cipher.TOY(post_XOR, key)
    return post_encrpyt
    pass
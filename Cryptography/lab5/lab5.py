#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 5 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

from Cryptodome.Util.strxor import strxor
import lab5_helper, aeskeyexp, binascii


def q1_forge_mac(message, leaky_hmac_verify=lab5_helper.leaky_hmac_verify_example):
    """Question 1: Timing attack on HMAC's equality test

    In this problem, you will forge an HMAC-SHA1 tag (without knowing the key) based solely on 
    the amount of time that the verify algorithm takes to validate a prospective tag. 

    The verification algorithm might leak information based on how long it takes to compute, 
    say, if it compares the computed value against the tag one bit at a time.

    The scenario:
        Pretend that Alice is sending authenticated messages to Bob using a key that they 
        know and **you do not**. Bob's code to verify that the messages are properly tagged is 
        given in the 'leaky_hmac_verify' function passed to this function. 
        In summary, his code computes the correct tag and compares it to the one that Alice provided. 

        However, Bob's equality comparison test is imperfect: if Alice's tag is not correct, 
        then Bob's code reveals (or "leaks") the location of the first difference between
        the correct tag and Alice's invalid attempt. 
        (This leaked bit simulates measuring the time it takes for Bob's verification algorithm to run.)

    Your Task:
        Take on the role of Mallory, and find a way to forge an HMAC tag on the following 41-byte message 
        without knowing the key:

        message = "This message was definitely sent by Alice"

        That is: your solution would send several message/tag pairs of your choice to Bob's 'leaky_hmac_verify' 
        routine. By observing Bob's responses, you should be able to forge the appropriate tag.
    Args:
        leaky_hmac_verify  (func)   :   the hmac verify function that Bob would run (check `lab5_helper.py` for an example)
    Output:
        ret     (str):  hex-encoded forged HMAC tag of the "message" given
    How to verify your answer:
        assert(q1_forge_mac(message="This message was definitely sent by Alice") ==
            lab5_helper.hmacsha1(key=lab5_helper.TEST_KEY, message="This message was definitely sent by Alice"))
    Note:
        The key passed to `leaky_hmac_verify` is unknown to you, so don't assume a determinstic output from
        `leaky_hmac_verify` given the same 'message' and 'claimed_tag'. We will test against multiple different
        keys.
    """
    byte = ""
    answer = ""
    for a in range(20):
        answer += byte
        for i in range(256):
            tag = answer + hex(i)[2:].rjust(2, "0")
            tag = tag.ljust(40, "0")
            arr = leaky_hmac_verify(message, tag)
            if arr[0] == True:
                return answer + tag[-2:]
            if arr[1] >= 8 * (a+1):
                byte = hex(i)[2:].rjust(2, "0")

# print(q1_forge_mac("This message was definitely sent by Alice"))
# 07a9248044e3013b88d149647140475719049b7e
# print(q1_forge_mac("This message was definitely sent by Alice") == lab5_helper.hmacsha1(lab5_helper.TEST_KEY, "This message was definitely sent by Alice"))


def q2_simple_aes_cache_attack(leaky_encipher=lab5_helper.leaky_encipher_example):
    """Question 2: Simple cache timing attack on AES

    As Mallory, you must determine the last round key at the very end of AES.
    Since you are a legitimate user on the machine, you're welcome to encipher files 
    whenever you'd like, and you can also introspect the state of the cache using techniques 
    like Prime+Probe that we discussed in class.

    Bob's code for file enciphering is provided as the 'leaky_encipher' routine passed to this function
    (Note: you can find an example of the 'leaky_encipher' routine in 'lab5_helper.py'). 

    Bob's routine does both of the above operations for you: it enciphers a file and then helpfully 
    tells you how the 10th round S-box lookups have influenced the state of the cache, so you don't 
    need to inspect it yourself. Hence, 'leaky_encipher' has two outputs: the actual ciphertext plus a 
    Python set stating which cachelines are accessed during the final round's SubBytes operation. 

    Recall that SubBytes works on a byte-by-byte basis: each byte of the state is used to fetch a 
    specific location within the S-box array. The 'leaky_encipher' routine tells you which elements of 
    the S-box array were accessed, which as you recall from Lecture 10 is correlated with the key. 

    I'll state two caveats upfront:
        -   This problem conducts a last-round attack, which is depicted in lecture 10 slide 7 but slightly different
            than the first-round attack we discussed for most of the lecture. As a result, the cache lines are correlated 
            with the last round key of AES, and not the first round key. 
            This is acceptable to Mallory because there's a known, public permutation that relates all of the round keys.

            In fact in my helper file 'aeskeyexp.py' I have provided a routine 'aes128_lastroundkey' that converts first -> last round keys. 
            I didn't actually give you the converse, but I assure you that it's equally as easy to compute. 
            Let's just declare victory as Mallory if we can find the last round key.

        -   Mallory cannot interrupt the state of execution of AES. She can only observe the contents of the cache after 
            it is finished. As a result: leaky_encipher only tells you the **set** of all table lookups made to the 10th 
            round S-box across all 16 bytes, without telling you which lookup is associated with which byte.

    Your Task:
        Complete this function with a solution that calls 'leaky_encipher' as many times as you wish 
        and uses the results to determine the key.
    Args:
        leaky_encipher  (func)  : performs an AES encipher on the input 16-bytes input `file_bytes`
            Args:
                file_bytes  (bytes)     : 16-bytes input to be passed to AES for enciphering
            Output:
                ret         (str, set)  : tuple with the actual ciphertext and a Python set stating which cachelines 
                                            are accessed during the final round's SubBytes operation.
    Output:
        ret             (str)   : hex-encoded 16-bytes string that represents the lastroundkey of AES in leaky_encipher
    How to verify your answer:
        assert(q2_simple_aes_cache_attack() ==
            aeskeyexp.aes128_lastroundkey(lab5_helper.TEST_KEY).hex())
    Note:
        The file `lab5_helper.py` contains some helper functions that you find useful in solving this question.
    """
    def find_cache_intersection_len_one(index):
        for i in range(1, 10):
            sample_message = str(7) * 32
            sample_message_encipher_cipher = leaky_encipher(binascii.unhexlify(sample_message))[0].hex()
            sample_message_encipher_cache = leaky_encipher(binascii.unhexlify(sample_message))[1]
            for x in range(2 ** 16):
                message = hex(x)[2:].rjust(32, "0")
                message_encipher = leaky_encipher(binascii.unhexlify(message))[0].hex()
                if message_encipher[index: index + 2] == sample_message_encipher_cipher[index: index + 2]:
                    new_message = message
                    cache_intersection = leaky_encipher(binascii.unhexlify(message))[
                        1].intersection(
                        sample_message_encipher_cache)
                    if len(list(cache_intersection)) == 1:
                        sinv_input = list(cache_intersection)[0]
                        message_encipher_byte = message_encipher[index: index + 2]
                        return [new_message, sinv_input, message_encipher_byte]


    def find_sinv(sinv_input):
        for x in range(256):
            res = lab5_helper.Sinv(x)
            if res == sinv_input:
                return hex(x)[2:].rjust(2, "0")

    # for i in range(16):
    #     print(find_sinv(i))
    # print("()()()")
    # for j in range(16):
    #     print(find_sinv(7*16 + j))

    def find_key_byte(index):
        arr = find_cache_intersection_len_one(2 * index)
        sinv = find_sinv(arr[1])
        a = bytes.fromhex(arr[2])
        b = bytes.fromhex(sinv)
        return binascii.hexlify(strxor(a, b)).decode("ascii")

    ret = ""
    for a in range(16):
        ret += find_key_byte(a)

    return ret

# print(q2_simple_aes_cache_attack())
# print("-------")
# # print(aeskeyexp.aes128_lastroundkey(lab5_helper.TEST_KEY).hex())
# print(q2_simple_aes_cache_attack() == aeskeyexp.aes128_lastroundkey(lab5_helper.TEST_KEY).hex())

# print(strxor(find_cache_intersection_len_one()[3][:2])
# print("Q2", q2_simple_aes_cache_attack())
# print("AES", aeskeyexp.aes128_lastroundkey(lab5_helper.TEST_KEY).hex())


def q3_realistic_aes_cache_attack(less_leaky_encipher=lab5_helper.less_leaky_encipher_example):
    """Question 3: Realistic cache timing attack on AES

    In this problem, you're still acting as Mallory and trying to perform a cache timing attack. 
    There's just one new hurdle that you must overcome. (As a consequence: do not attempt to solve 
    this problem until you have already solved Question 2.)

    I made one unrealistic assumption in the 'leaky_encipher' routine:
    I provided you with the set of bytes that were accessed in the final round of AES.
    Real caches unfortunately do not provide byte-level accuracy. I'll spare you the details; 
    the upshot is that it is common for 16 values of the SubBytes array to fit within a single cacheline.

    That is: suppose Bob weren't running AES at all, but instead only makes a single table 
    lookup S[x] into the SubBytes array S. By observing which portion of the cache is activated, 
    a cache attack would let Mallory know whether Bob's access x was in the range 0-15, or the range 16-31, 
    or the range 32-47, ... or the range 240-255. However, Mallory couldn't tell anything beyond that. 
    Put another way: Mallory can learn the upper 4 bits of x but not the lower 4 bits.

    The 'lab5_helper.py' file contains Bob's code for this problem. It is the routine less_leaky_encipher_example 
    that only provides (the set of) the upper 4 bits of the location of each table lookup to Mallory; it otherwise 
    runs similarly to the code in Question 2.

    Your Task:
        Perform a cache timing attack even in this restricted setting. Your input-output behavior should 
        be the same as stated in Question 2.
        (The solution to this problem is pretty much exactly what Osvik, Shamir, and Tromer did to break 
        Linux's full disk encryption software, called dmcrypt.)
    """

    # TODO: Complete me!
    def find_cache_intersection_len_one(index, start):
        for i in range(start, 10):
            sample_message = str(i) * 32
            sample_message_encipher_cipher = \
            less_leaky_encipher(binascii.unhexlify(sample_message))[0].hex()
            sample_message_encipher_cache = less_leaky_encipher(binascii.unhexlify(sample_message))[
                1]
            # print(sample_message)
            # print(sample_message_encipher_cipher)
            # print(sample_message_encipher_cache)
            # print("--")
            cache_intersection = sample_message_encipher_cache
            for x in range(2 ** 16):
                message = hex(x)[2:].rjust(32, "0")
                message_encipher = less_leaky_encipher(binascii.unhexlify(message))[0].hex()
                if message_encipher[index: index + 2] == sample_message_encipher_cipher[index: index + 2]:
                    new_message = message
                    # print(message)
                    # print(message_encipher)
                    new_message_cache = less_leaky_encipher(binascii.unhexlify(message))[1]
                    # print(new_message_cache)
                    if len(list(cache_intersection)) > 1:
                        cache_intersection = new_message_cache.intersection(cache_intersection)
                        # print("CI:", cache_intersection)
                    else:
                        sinv_input = list(cache_intersection)[0]
                        message_encipher_byte = message_encipher[index: index + 2]
                        # print("Below is RETURN")
                        return [new_message, sinv_input, message_encipher_byte, i]

    def find_sinv(sinv_input):
        myList = []
        outputList = []
        for a in range(16):
            myList.append(16 * sinv_input + a)
        # print(myList)
        for x in range(256):
            res = lab5_helper.Sinv(x)
            for i in range(16):
                if res == myList[i]:
                    outputList.append(hex(x)[2:].rjust(2, "0"))
        return outputList

    def find_key_byte(index):
        arr = find_cache_intersection_len_one(2 * index, 1)
        arr2 = find_cache_intersection_len_one(2 * index, arr[3] + 1)
        # print("arr", arr)
        # print("arr2", arr2)
        sinv_arr1 = find_sinv(arr[1])
        sinv_arr2 = find_sinv(arr2[1])
        post_xor = sinv_arr1
        post_xor2 = sinv_arr2
        # print('find', sinv_arr1)
        # print('find2', sinv_arr2)
        for i in range(16):
            post_xor[i] = binascii.hexlify(strxor(bytes.fromhex(sinv_arr1[i]), bytes.fromhex(arr[2]))).decode('ascii')
            post_xor2[i] = binascii.hexlify(strxor(bytes.fromhex(sinv_arr2[i]), bytes.fromhex(arr2[2]))).decode('ascii')
        # print("post1: ", post_xor)
        # print("post2", post_xor2)
        # TODO: CHANGE TO SET
        cache_intersection_8bits = intersection(post_xor, post_xor2)
        while len(cache_intersection_8bits) > 1:
            # print(cache_intersection_8bits)
            arr3 = find_cache_intersection_len_one(2 * index, arr2[3] + 1)
            sinv_arr3 = find_sinv(arr3[1])
            post_xor3 = sinv_arr3
            # print('arr3', arr3)
            # print('find3', sinv_arr3)
            for j in range(16):
                post_xor3[j] = binascii.hexlify(strxor(bytes.fromhex(sinv_arr3[j]), bytes.fromhex(arr3[2]))).decode(
                    'ascii')
            # print('post3', post_xor3)
            cache_intersection_8bits = intersection(cache_intersection_8bits, post_xor3)
            arr2[3] = arr3[3]
        return cache_intersection_8bits

    def intersection(lst1, lst2):
        return list(set(lst1) & set(lst2))

    ret = ""
    for k in range(16):
        ret += find_key_byte(k)[0]
    return ret



# import time
# start_time = time.time()
# a = q3_realistic_aes_cache_attack()
# b = q2_simple_aes_cache_attack()
# print(a)
# print("FINAL KEY: ", b)
# print(a == b)
# print("--- %s seconds ---" % (time.time() - start_time))
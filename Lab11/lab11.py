#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 11 ##############################################

"""
List you collaborators here:
                                Harrison Richmond
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import lab11_helper, random
from cryptography.fernet import InvalidToken


def q1_difference_propagation(Sbox):
  """Question 1: Constructing a difference propagation table

  In this problem, you must write the code to produce a difference propagation
  table like the one shown in Lecture 20.

  Your Task:
    Construct this function to return the difference propagation table
    corresponding to a particular `Sbox` (where the input is a 2-dimensional
    list the represents an 8-bit Sbox).

  Notes:
    Remember that the difference propagation table is a 256 x 256 matrix where
    each entry is in the range 0-256. The matrix is constructed as follows:
    the value in the (d_in, d_out) entry (0-indexed) equals the number of
    pairs of inputs and outputs (x, y= S(x)) and (x', y' = S(x')) such that
    x XOR x' = d_in and y XOR y' = d_out (i.e., the difference of inputs is d_in
    and the difference of outputs is d_out).

    Your code must work for any 8-bit S-box that we provide as input.

    Your returned table should be a 2d-array (rather than a 1d-array) that you 
    can index as follows:
          ```
            val = table[r][c]
          ```
  Args:
    Sbox    (func(int):int):  An S-Box substitution function that takes in a
                  byte input (value from 0-255) and returns a byte
                  output (value from 0-255)
                    (check lab11_helper.test_sbox as an example)
  Output:
    ret     (list(list(int))): The difference propagation table as a 256 x 256
                  matrix where each entry is in the range 0-256
  How to verify your solution:
  ```
    assert(q1_difference_propagation(lab11_helper.test_Sbox) == lab11_helper.test_diff_prop_table)
  ```
  """

  #TODO: Complete me!
  n = 256
  arr = []
  test = [[0 for x in range(n)] for y in range(n)]
  for j in range(n):
    input_diff = j
    for i in range(n):
      input1 = i
      input2 = i ^ input_diff
      output1 = Sbox(input1)
      output2 = Sbox(input2)
      output_diff = output1 ^ output2
      test[input_diff][output_diff] += 1
  return test


def q2_simple_garbled_circuit(garbled_circuit, garbler_input, OT):
  """Question 2: Simple Garbled Circuit

  Garbled circuit is a cryptographic protocol that enables two-party secure
  computation in which two mistrusting parties can jointly evaluate a function
  over their private inputs without the presence of a trusted third party. In
  garbled circuits, there are two main parties: the garbler and the evaluator.

  For a more in-depth explanation on Garbled circuits, please refer to
  Lecture 20.

  Your Task:
    In this question, you'll be simulating the role of an evaluator. For
    simplicity, the circuit we're intrested in computing is constructed as 
    follows:

                  a    b                      c      d
                  +    +                      +      +
               +  |    | +                    |      |
              X \ |    | / X                  v      v
              XX -v----v- XX               XXX+XXXXXX+XXX
              X XXXXXXXXXX X               X            X
              X            X               X            X
              X            X               X     AND    X
              X     XOR    X               X            X
              X            X               X            X
              XX          XX               XX          XX
               XX        XX                 XX        XX
                XX      XX                   XX      XX
                  XXX+XXX                      XXX+XXX
                     |                            |
                     |                            |
                     |                            |
                     |                            |
                     |                            |
                     +----------+      +----------+
                                |      |
                                |      |
                             X  |      |  X
                             XX v      v XX
                             X X+XXXXXX+X X
                             X            X
                             X            X
                             X     OR     X
                             X            X
                             XX          XX
                              XX        XX
                               XX      XX
                                 XXX+XXX
                                    |
                                    v
                                  output

      As an evaluator, you'll be providing the inputs `a` and `c`, and the other 
    party (the "garbler") will be providing the other two inputs `b` and `d`.

  Notes:
      - You'll be picking the values of `a` and `c` as part of your
        implementation, you can choose any bit pair that you like.
    
    - When using the Oblivious Transfer (OT) function, make sure to pass the 
      gate type as the first argument, there are two types that you can use 
      (XOR_GATE and AND_GATE), you can find the types defined in lab11_helper.
      For example, doing the following will return the encryption of the `a` 
      value from the figure above:
      ```
        from lab11_helper import XOR_GATE
        encrypted_xor_input = OT(XOR_GATE, 0) #a=0 in this case
      ```
    - You can call the OT function only **once** per gate type.

    - The encryption algorithm used to encrypt the labels is the `Fernet`,
      you can find it in the `cryptography` library as follows:
      `from cryptography.fernet import Fernet`
    
    - Fernet is an Authenticated encryption algorithm, therefore a decryption
      of an invalid ciphertext will throw an `cryptography.fernet.InvalidToken` 
      exception.
  
    - When decrypting a ciphertext, make sure to take into consideration that
      the encryption order is enc_k1(enc_k2(label)), feel free to use the
      helper function `lab11_helper.doubly_authenticated_decryption` to 
      perform the decryption (highly recommend).
    
    - For simplicity, the output of the last "OR" gate will not be garbled 
      (we wont be using lables to represents the `0` and `1`), instead, 
      we'll represent 0 as a the hex value `00`, and 1 as the hex value `01`. 
      You should simply return the hex string `00` or `01` as the result.
      
  Args:
      garbled_circuit (lab11_helper.GarbledCiphertexts):  An object containing
        the ciphertexts for the truth table of each gate (note the the
        ciphertexts per gate are shuffled, so don't assume a specific order)
      
      garbler_input   (list(str)): The encrypted lables of the values of `b` 
        and `d` that the garbler choose.
    
      OT              (func(GATE_TYPE, int):str): Oblivious Transfer function, 
        takes in a gate type and a bit input, returns the corresponding label 
        for that input bit (as a hex-encoded string).
  
  Output:
      ret             (str):  the result of the circuit on the inputs a, b, c
        and d. The result should be a hex-encoded string that represents the bit
        value `0` or `1`.
  
  How to verify your solution:
  ```
    assert(q2_simple_garbled_circuit(*lab11_helper.test_input) == '01')
  ```
    Note that the test case above is the result of the evaluator picking `a=1,
    c=1` and the garbler picking `b=1, d=1`. You can test your own
    implementation with any other bit pairs (for the evaluator side) and check
    the output by manually going over the circut above.
  """

  #TODO: Complete me!
  xor_garbled = garbled_circuit.XOR_ciphertexts
  and_garbled = garbled_circuit.AND_ciphertexts
  or_garbled = garbled_circuit.OR_ciphertexts

  xor_OT = OT(0,0)
  and_OT = OT(1,1)

  post_xor = ""  # a and b
  post_and = ""  # c and d
  post_or = ""  # post_xor and post_and

  for cipher_text in xor_garbled:
    try:
      post_xor = lab11_helper.doubly_authenticated_decryption(xor_OT, garbler_input[0], cipher_text)
    except(InvalidToken):
      pass
  for cipher_text in and_garbled:
    try:
      post_and = lab11_helper.doubly_authenticated_decryption(and_OT, garbler_input[1], cipher_text)
    except(InvalidToken):
      pass
  for cipher_text in or_garbled:
    try:
      post_or = lab11_helper.doubly_authenticated_decryption(post_xor, post_and, cipher_text)
    except(InvalidToken):
      pass

  return post_or


def q3_stack_exchange():
  """Question 3: Answer a Question on Stack Exchange

  Your Task:
    Spread your new-found knowledge of applied cryptography to others.
    Concretely, find a question on https://crypto.stackexchange.com
    pertaining to material that we've covered in this course, and answer it.

  Requirements:
    - Don't post a question to yourself; that's boring!

    - Questions with the following tags are most likely to be pertinent to
      the class material: aes, authentication, block cipher,
      brute-force-attack, cbc, cryptanalysis, encryption, hash,
      initialization-vector, mac, modes-of-operation, padding, and symmetric.
      (I'm sure there are others.)

    - Try to find a question that either has 0 prior answers or for which
      the prior answers seem to be incorrect. In particular, avoid any
      question with many answers, especially several new answers that are
      likely to come from your classmates. (But if you wish to answer a
      question with 1-2 previous answers, that is okay as long as your answer
      is somehow different than the prior ones.)
  
  Privacy notice:
    I don't want to force you to post an answer to the Internet. Ergo, you
    will obtain full credit on this assignment simply by finding a question
    on Stack Exchange and answering it locally to me. With that having been
    said: I do encourage you to post your answer publicly if you're
    comfortable doing so.

  Args:
    None
  
  Output:
    ret (list(str, str, str)): A list (or a tuple) with the following items:
          - The URL of the Stack Exchange question that you wish to consider.
          - The text of the question.
          - Your answer.
  """

  #TODO: Complete me!
  url = "https://crypto.stackexchange.com/questions/32404/when-we-use-one-time-pad-twice-in-two-different-ways/70207#70207"
  text = "When we use one time pad TWICE in two different ways"  \
         "Assumption and Notations: All the values defined over the field 𝔽𝑝, where 𝑝 is a large prime number. " \
         "We denote multiplicative inverse of value 𝑣 by 𝑣−1. All values are non-zero values.We all know that one " \
         "time pad should not be used more than once. Let 𝑣1 = 𝑏 ⋅𝑧" \
         "𝑣2 = 𝑏 + 𝑧 − 1. Where 𝑧 is a uniformly random element of " \
         "the field and 𝑏 is a fixed value. ================================================ Question: given 𝑣1 and " \
         "𝑣2 can an adversary learn anything about the values 𝑏 (and 𝑧)?"
  answer = "Answer is in latex (can be found on website for better format): " \
           "$ v_1 = b \cdot z \\ v_2 = b + z^{-1} $ Given the following equations, we can rearrange the following " \
           "into: $ v_1 \cdot z^{-1} = b \\ v_2 - z^{-1} = b \\ v_1 \cdot z^{-1} =  v_2 - z^{-1} \\ v_1 \cdot z^{-1}" \
           " + z^{-1} = v_2 \\ z^{-1} (v_1 + 1) = v_2 \\ v_1 + 1 = v_2 * z \hspace{50pt} \text{(multiply both side " \
           "by z)} \\ z = (v_1 + 1) \cdot (v_2)^{-1}$ Once we find z, we can use the first equation $ v_1 = b \cdot" \
           " z $ to find b. $ v_1 = b \cdot (v_1 + 1) \cdot (v_2)^{-1} \\ b = v_1 \cdot v_2 \cdot (v_1 + 1) ^{-1}$"
  return [url, text, answer]

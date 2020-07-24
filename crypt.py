#This file is responsible for encrypting and decrypting
import math


key = "HACK"

def encrypt_message(msg):
    cipher = ""

    k_index = 0

    msg_len = float(len(msg))
    msg_list = list(msg)
    key_list = sorted(list(key))

    col = len(key)

    row = int(math.ceil(msg_len / col))

    fill_null = int((row * col) - msg_len)
    msg_list.extend('_' * fill_null)

    matrix = [msg_list[i: i + col]
              for i in range(0, len(msg_list), col)]

    for _ in range(col):
        curr_idx = key.index(key_list[k_index])
        cipher += ''.join([row[curr_idx]
                           for row in matrix])
        k_index += 1

    return cipher

def decrypt_message(cipher):
    msg = ""
    k_indx = 0

    msg_index = 0
    msg_len = float(len(cipher))
    msg_lst = list(cipher)

    col = len(key)
    row = int(math.ceil(msg_len / col))
    key_list = sorted(list(key))

    dec_cipher = []
    for _ in range(row):
        dec_cipher += [[None] * col]

    for _ in range(col):
        curr_idx = key.index(key_list[k_indx])

        for j in range(row):
            dec_cipher[j][curr_idx] = msg_lst[msg_index]
            msg_index += 1
        k_indx += 1

    try:
        msg = ''.join(sum(dec_cipher, []))
    except TypeError:
        raise TypeError("This program cannot",
                        "handle repeating words.")

    null_count = msg.count('_')

    if null_count > 0:
        return msg[: -null_count]

    return msg
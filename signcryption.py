from ecpy.curves import Curve, Point
import random
from math import floor, ceil, log2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from typing import Tuple
from Crypto.Util.Padding import pad, unpad
import json

from constants import CURVE


def gen_keys():
    priv_key = random.randint(1, CURVE.order - 1)
    pub_key = priv_key * CURVE.generator
    return priv_key, pub_key


def signcryption(message: str, send_id: int, recv_id: int, send_priv_key: int,
                 recv_pub_key: Point):
    while True:
        # 2
        r = random.randint(1, CURVE.order - 1)
        # 3
        R = r * CURVE.generator
        # 4
        f = floor(log2(CURVE.order)) + 1
        xR_wave = (2 ** ceil(f / 2)) * (R.x % (2 ** ceil(f / 2)))
        K = (r + xR_wave * send_priv_key) * recv_pub_key
        if K.is_infinity:
            continue

        k_input = str(K.x) + str(send_id) + str(K.y) + str(recv_id)
        k = SHA256.new(k_input.encode()).digest()
        # 5
        iv = b'\x00' * 15 + b'\xb3'
        cipher = AES.new(k, AES.MODE_CBC, iv=iv)
        C = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
        # 6
        t_input = C + (str(R.x) + str(send_id) + str(R.y) + str(recv_id)).encode()
        t = SHA256.new(t_input).digest()
        t = int.from_bytes(t, 'big')
        s = (t * send_priv_key - r) % CURVE.order
        return R, C, s


def unsigncryption(recv_data: Tuple[Point, bytes, int], send_id: int, recv_id: int,
                   send_pub_key: Point, recv_priv_key: int):
    R, C, s = recv_data

    # 2
    f = floor(log2(CURVE.order)) + 1
    xR_wave = (2 ** ceil(f / 2)) * (R.x % (2 ** ceil(f / 2)))  # okay
    K = recv_priv_key * (R + xR_wave * send_pub_key)
    k_input = str(K.x) + str(send_id) + str(K.y) + str(recv_id)
    k = SHA256.new(k_input.encode()).digest()  # okay
    # 3
    iv = b'\x00' * 15 + b'\xb3'
    cipher = AES.new(k, AES.MODE_CBC, iv=iv)
    M = unpad(cipher.decrypt(C), AES.block_size)
    M = M.decode("utf-8")
    # 4
    t_input = C + (str(R.x) + str(send_id) + str(R.y) + str(recv_id)).encode()
    t = SHA256.new(t_input).digest()
    t = int.from_bytes(t, 'big')  # TODO OKAY

    if (s * CURVE.generator) + R == t * send_pub_key:
        return M
    else:
        return None


def main():
    # Из статьи: https://arxiv.org/abs/1002.3316
    curve = Curve.get_curve('NIST-P192')

    ID_A, ID_B = 1, 2
    orig_message = 'Hello world! Привет'
    priv_A, pub_A = gen_keys()
    priv_B, pub_B = gen_keys()
    to_recv = signcryption(orig_message, ID_A, ID_B, priv_A, pub_B)
    message = unsigncryption(to_recv, ID_A, ID_B, pub_A, priv_B)
    if message == orig_message:
        print("HOORAY! =)")
    else:
        print("BAD! =<")


def check_curve():
    pass  # TODO


def check_keys():
    pass


if __name__ == "__main__":
    main()
    pass

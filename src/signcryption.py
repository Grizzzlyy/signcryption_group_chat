"""
Implementation of signcryption scheme, proposed in https://arxiv.org/abs/1002.3316
"""
from typing import List
import string
import random
from math import floor, ceil, log2, sqrt
from base64 import b64encode, b64decode
import time

from ecpy.curves import Curve, TwistedEdwardCurve
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from typing import Tuple
from Crypto.Util.Padding import pad, unpad
from sympy import isprime

from constants import CURVE, IV


# Returns None if curve is suitable, otherwise reason why it's not suitable
def check_curve(curve: Curve) -> str | None:
    if type(curve) == TwistedEdwardCurve:
        return "TwistedEdwardCurve"

    q = curve.field
    n = curve.order
    a, b = curve.a, curve.b

    if not isprime(q):
        return "'q' is not prime"

    # Check non singular
    if 4 * (a ** 3) + 27 * (b ** 2) % q == 0:
        return "singular curve"

    # Guard against small subgroup attacks
    if n <= 4 * sqrt(q):
        return "small subgroup attacks"

    # Protect against other known attacks on special classes of elliptic curves
    for i in range(1, 21):
        if q ** i - 1 % n == 0:
            return "small subgroup attacks"

    # Intractability of ECDLP
    if n <= 2 ** 160:
        return "ECDLP is tractable"

    return None


def gen_keys(curve: Curve) -> (int, List[int]):
    priv_key = random.randint(1, curve.order - 1)
    pub_key = curve.encode_point(priv_key * curve.generator)
    return priv_key, pub_key


def signcryption(curve: Curve, message: str, send_id: str, recv_id: str, send_priv_key: int,
                 recv_pub_key: List[int]) -> (List[int], str, int):
    recv_pub_key = curve.decode_point(recv_pub_key)

    while True:
        # 2
        r = random.randint(1, curve.order - 1)
        # 3
        R = r * curve.generator
        # 4
        f = floor(log2(curve.order)) + 1
        xR_wave = (2 ** ceil(f / 2)) * (R.x % (2 ** ceil(f / 2)))
        K = (r + xR_wave * send_priv_key) * recv_pub_key
        if K.is_infinity:
            continue

        k_input = str(K.x) + send_id + str(K.y) + recv_id
        k = SHA256.new(k_input.encode()).digest()
        # 5
        cipher = AES.new(k, AES.MODE_CBC, iv=IV)
        C = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
        # 6
        t_input = C + (str(R.x) + send_id + str(R.y) + recv_id).encode()
        t = SHA256.new(t_input).digest()
        t = int.from_bytes(t, 'big')
        s = (t * send_priv_key - r) % curve.order

        R = curve.encode_point(R)
        C = b64encode(C).decode("utf-8")
        return R, C, s


def unsigncryption(curve: Curve, signcrypted_data: Tuple[List[int], str, int], send_id: str, recv_id: str,
                   send_pub_key: List[int],
                   recv_priv_key: int) -> str | None:
    R, C, s = signcrypted_data
    send_pub_key = curve.decode_point(send_pub_key)
    R = curve.decode_point(R)
    C = b64decode(C.encode("utf-8"))

    # 2
    f = floor(log2(curve.order)) + 1
    xR_wave = (2 ** ceil(f / 2)) * (R.x % (2 ** ceil(f / 2)))
    K = recv_priv_key * (R + xR_wave * send_pub_key)
    k_input = str(K.x) + str(send_id) + str(K.y) + str(recv_id)
    k = SHA256.new(k_input.encode()).digest()
    # 3
    cipher = AES.new(k, AES.MODE_CBC, iv=IV)
    M = unpad(cipher.decrypt(C), AES.block_size)
    M = M.decode("utf-8")
    # 4
    t_input = C + (str(R.x) + str(send_id) + str(R.y) + str(recv_id)).encode()
    t = SHA256.new(t_input).digest()
    t = int.from_bytes(t, 'big')

    if (s * curve.generator) + R == t * send_pub_key:
        return M
    else:
        return None


def main():
    # Test curves
    print("Checking if curves suitable for signcryption...")
    for curve_name in CURVE.get_curve_names():
        curve = Curve.get_curve(curve_name)
        res = check_curve(curve)
        if res:
            print(f"{curve.name}: BAD ({res})")
        else:
            print(f"{curve.name}: OKAY")

    # Test signcryption
    ID_A, ID_B = 'Alice', 'Bob'
    priv_A, pub_A = gen_keys(CURVE)
    priv_B, pub_B = gen_keys(CURVE)
    orig_message = 'Hello world! Привет мир!'
    signcrypted_msg = signcryption(CURVE, orig_message, ID_A, ID_B, priv_A, pub_B)
    message = unsigncryption(CURVE, signcrypted_msg, ID_A, ID_B, pub_A, priv_B)
    if message == orig_message:
        print("\nModule 'signcryption' works fine.")
    else:
        print("\nModule 'signcryption' ERROR.")

    # Test speed
    def msg_generator(size, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    msg_sizes = [512, 1024, 2048]
    curve_names = ['NIST-P192', 'NIST-P224', 'NIST-P256']
    msg_num = 200

    print("\nTime test")
    for msg_size in msg_sizes:
        print(f"msg size: {msg_size}")
        for curve_name in curve_names:
            curve = Curve.get_curve(curve_name)
            print(f"\tcurve: {curve.name}")
            msgs = [msg_generator(msg_size) for _ in range(msg_num)]
            priv_A, pub_A = gen_keys(curve)
            priv_B, pub_B = gen_keys(curve)
            s_start = time.time()
            signcrypted_msgs = [signcryption(curve, msg, 'Alice', 'Bob', priv_A, pub_B) for msg in msgs]
            s_end = time.time()
            print(f"\t\tsigncryption: {(s_end - s_start) / msg_num} s/iter")
            u_start = time.time()
            unsigncrypted_msgs = [unsigncryption(curve, s_msg, 'Alice', 'Bob', pub_A, priv_B) for s_msg in
                                  signcrypted_msgs]
            u_end = time.time()
            print(f"\t\tunsigncryption: {(u_end - u_start) / msg_num} s/iter")


if __name__ == "__main__":
    main()

"""
Implementation of signcryption scheme, proposed in https://arxiv.org/abs/1002.3316
"""
from typing import List
from ecpy.curves import Curve, TwistedEdwardCurve
import random
from math import floor, ceil, log2, sqrt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from typing import Tuple
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
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


def gen_keys() -> (int, List[int]):
    priv_key = random.randint(1, CURVE.order - 1)
    pub_key = CURVE.encode_point(priv_key * CURVE.generator)
    return priv_key, pub_key


def signcryption(message: str, send_id: str, recv_id: str, send_priv_key: int,
                 recv_pub_key: List[int]) -> (List[int], str, int):
    recv_pub_key = CURVE.decode_point(recv_pub_key)

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

        k_input = str(K.x) + send_id + str(K.y) + recv_id
        k = SHA256.new(k_input.encode()).digest()
        # 5
        cipher = AES.new(k, AES.MODE_CBC, iv=IV)
        C = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
        # 6
        t_input = C + (str(R.x) + send_id + str(R.y) + recv_id).encode()
        t = SHA256.new(t_input).digest()
        t = int.from_bytes(t, 'big')
        s = (t * send_priv_key - r) % CURVE.order

        R = CURVE.encode_point(R)
        C = b64encode(C).decode("utf-8")
        return R, C, s


def unsigncryption(signcrypted_data: Tuple[List[int], str, int], send_id: str, recv_id: str, send_pub_key: List[int],
                   recv_priv_key: int) -> str | None:
    R, C, s = signcrypted_data
    send_pub_key = CURVE.decode_point(send_pub_key)
    R = CURVE.decode_point(R)
    C = b64decode(C.encode("utf-8"))

    # 2
    f = floor(log2(CURVE.order)) + 1
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

    if (s * CURVE.generator) + R == t * send_pub_key:
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
    priv_A, pub_A = gen_keys()
    priv_B, pub_B = gen_keys()
    orig_message = 'Hello world! Привет мир!'
    signcrypted_msg = signcryption(orig_message, ID_A, ID_B, priv_A, pub_B)
    message = unsigncryption(signcrypted_msg, ID_A, ID_B, pub_A, priv_B)
    if message == orig_message:
        print("\nModule 'signcryption' works fine.")
    else:
        print("\nModule 'signcryption' ERROR.")


if __name__ == "__main__":
    main()

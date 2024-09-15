from ecpy.curves import Curve, Point
from signcryption import gen_keys

def challenge(pub_key: Point):


if __name__ == "__main__":
    curve = Curve.get_curve('NIST-P192')


    priv_A, pub_A = gen_keys(curve)



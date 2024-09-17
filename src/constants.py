from ecpy.curves import Curve

# Curve for signcryption. Parameters: https://neuromancer.sk/std/nist/P-192
CURVE = Curve.get_curve('NIST-P192')
IV = b'\x00' * 15 + b'\xb3' # Input vector for AES256-CBC
BUFF_SIZE = 2048  # Client-server buffer-size

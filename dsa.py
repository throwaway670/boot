import hashlib
import secrets

def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def _modinv(a, m):
    a %= m
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse.")
    return x % m

def _hash_to_int(msg: str, q: int) -> int:
    h = hashlib.sha1(msg.encode('utf-8')).hexdigest() # SHA-1 hash
    return int(h, 16) % q

def dsa_keygen(p: int, q: int, g: int, x: int | None = None) -> tuple[int, int]:
    if x is None: # generate private key x
        x = secrets.randbelow(q - 1) + 1  # x in [1, q-1]
    y = pow(g, x, p) # public key y = g^x mod p
    return x, y # return private x and public y keys

def dsa_sign(p: int, q: int, g: int, x: int, message: str, k: int | None = None) -> tuple[int, int]:
    hm = _hash_to_int(message, q) # hash message to integer modulo q
    tries = 0 # attempt counter
    while True:
        tries += 1
        if k is None: # generate per-message secret k
            k = secrets.randbelow(q - 1) + 1 # k in [1, q-1]
        if _egcd(k, q)[0] != 1: # ensure k is coprime with q
            k = None
            if tries > 64:
                raise ValueError("Failed to find valid k.")
            continue
        r = pow(g, k, p) % q # r = (g^k mod p) mod q
        if r == 0:
            k = None
            if tries > 64:
                raise ValueError("Failed to find valid k.")
            continue
        kinv = _modinv(k, q) # k^(-1) mod q
        s = (kinv * (hm + x * r)) % q # s = k^(-1)(H(m) + x*r) mod q
        if s == 0:
            k = None
            if tries > 64:
                raise ValueError("Failed to find valid k.")
            continue
        return r, s

def dsa_verify(p: int, q: int, g: int, y: int, message: str, r: int, s: int) -> bool:
    if not (0 < r < q and 0 < s < q):
        return False
    hm = _hash_to_int(message, q) # hash message to integer modulo q
    w = _modinv(s, q) # w = s^(-1) mod q
    u1 = (hm * w) % q # u1 = H(m)*w mod q
    u2 = (r * w) % q # u2 = r*w mod q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p # v = (g^u1 * y^u2) mod p
    v %= q # v = v mod q
    return v == r # verify signature

if __name__ == "__main__":
    # Parameters (must satisfy: q | (p-1) and g^q ≡ 1 (mod p))
    p = int(input("Enter prime p: "))
    q = int(input("Enter prime q: "))
    g = int(input("Enter generator g: "))
    x_in = input("Enter private key x (blank to random in [1,q-1]): ").strip()
    x = int(x_in) if x_in else None

    # Key generation
    x, y = dsa_keygen(p, q, g, x)
    print(f"Public key y = {y}")

    # Sign
    msg = input("Enter message to sign: ")
    k_in = input("Enter per-message secret k (blank to random): ").strip()
    k = int(k_in) if k_in else None
    try:
        r, s = dsa_sign(p, q, g, x, msg, k)
    except ValueError as e:
        print(str(e))
        exit(1)
    print(f"Signature r = {r}")
    print(f"Signature s = {s}")

    # Verify
    ok = dsa_verify(p, q, g, y, msg, r, s)
    print(f"Verified: {ok}")

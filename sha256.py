U32_MASK = 0xFFFFFFFF

def u32(x: int) -> int:
    return x & U32_MASK

def rotr(x: int, n: int) -> int:
    n &= 31
    if n == 0:
        return u32(x)
    return u32((x >> n) | ((x << (32 - n)) & U32_MASK))

def shr(x: int, n: int) -> int:
    n &= 31
    return (x & U32_MASK) >> n

def ch(x: int, y: int, z: int) -> int:
    # Choose: (x & y) ^ (~x & z)
    return u32((x & y) ^ (~x & z))

def maj(x: int, y: int, z: int) -> int:
    # Majority: (x & y) ^ (x & z) ^ (y & z)
    return u32((x & y) ^ (x & z) ^ (y & z))

def big_sigma0(x: int) -> int:
    # Σ0(x) = ROTR^2(x) ^ ROTR^13(x) ^ ROTR^22(x)
    return u32(rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))

def big_sigma1(x: int) -> int:
    # Σ1(x) = ROTR^6(x) ^ ROTR^11(x) ^ ROTR^25(x)
    return u32(rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))

def small_sigma0(x: int) -> int:
    # σ0(x) = ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)
    return u32(rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3))

def small_sigma1(x: int) -> int:
    # σ1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
    return u32(rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10))

# SHA-256 constants
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
)

# Initial hash values (H0..H7)
IV: tuple[int, ...] = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
)

def _to_bytes(data):
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)

def _pad(msg_bytes: bytes) -> bytes:
    ml = len(msg_bytes)
    bit_len = ml * 8
    # append '1' bit (0x80), then k zero bytes so that length ≡ 56 mod 64, then 64-bit big-endian length
    padded = msg_bytes + b'\x80'
    pad_len = (56 - (len(padded) % 64)) % 64
    padded += b'\x00' * pad_len
    padded += bit_len.to_bytes(8, byteorder='big')
    return padded

def _chunks(b: bytes, size: int):
    for i in range(0, len(b), size):
        yield b[i:i+size]

def sha256_digest(data) -> bytes:
    msg = _to_bytes(data)
    H: list[int] = [int(v) for v in IV]

    for block in _chunks(_pad(msg), 64):
        # Prepare message schedule
        W = [0] * 64
        for i in range(16):
            W[i] = int.from_bytes(block[4*i:4*i+4], byteorder='big')
        for i in range(16, 64):
            t = (small_sigma1(W[i-2]) + W[i-7] + small_sigma0(W[i-15]) + W[i-16])
            W[i] = u32(t)

        a, b, c, d, e, f, g, h = H
        for i in range(64):
            T1 = u32(h + big_sigma1(e) + ch(e, f, g) + K[i] + W[i])
            T2 = u32(big_sigma0(a) + maj(a, b, c))
            h = g
            g = f
            f = e
            e = u32(d + T1)
            d = c
            c = b
            b = a
            a = u32(T1 + T2)

        H[0] = u32(H[0] + a)
        H[1] = u32(H[1] + b)
        H[2] = u32(H[2] + c)
        H[3] = u32(H[3] + d)
        H[4] = u32(H[4] + e)
        H[5] = u32(H[5] + f)
        H[6] = u32(H[6] + g)
        H[7] = u32(H[7] + h)

    return b"".join(hh.to_bytes(4, byteorder='big') for hh in H)

def sha256_hexdigest(data) -> str:
    return sha256_digest(data).hex()

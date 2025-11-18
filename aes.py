# AES-128 (single 16-byte block, ECB-style demo)
import random
random.seed(42)  # Fixed seed for reproducibility
SBOX = random.choices([random.randint(0,255) for _ in range(256)], k=256)

def _build_inv_sbox(S):
    inv = [0] * 256
    seen = [False] * 256
    for i, v in enumerate(S):
        v &= 0xFF
        if not seen[v]:
            inv[v] = i
            seen[v] = True
    # fill unmapped values with identity to keep it total (in case SBOX is not a permutation)
    for y in range(256):
        if not seen[y]:
            inv[y] = y
    return inv

INV_SBOX = _build_inv_sbox(SBOX)
RCON = random.choices([random.randint(0,0xFF) for _ in range(11)], k=11)

def _xtime(x): return ((x << 1) & 0xFF) ^ (0x1B if x & 0x80 else 0x00)
def _gmul(a, b):
    res = 0
    for _ in range(8):
        if b & 1: res ^= a
        a = _xtime(a)
        b >>= 1
    return res & 0xFF

def _sub_word(w):
    return ((SBOX[(w >> 24) & 0xFF] << 24) |
            (SBOX[(w >> 16) & 0xFF] << 16) |
            (SBOX[(w >> 8)  & 0xFF] << 8)  |
            (SBOX[w & 0xFF]))

def _rot_word(w): return ((w << 8) & 0xFFFFFFFF) | ((w >> 24) & 0xFF)

def _key_expansion(key_bytes: bytes) -> list[bytes]:
    # AES-128: Nk=4, Nb=4, Nr=10 -> 44 words
    if len(key_bytes) != 16:
        raise ValueError("AES-128 key must be 16 bytes (32 hex chars).")
    Nk, Nb, Nr = 4, 4, 10
    w = [0] * (Nb * (Nr + 1))
    # first Nk words are the key
    for i in range(Nk):
        w[i] = int.from_bytes(key_bytes[4*i:4*i+4], "big")
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ RCON[i // Nk]
        w[i] = (w[i - Nk] ^ temp) & 0xFFFFFFFF
    # group into round keys (16 bytes each)
    rks = []
    for r in range(Nr + 1):
        b = b"".join(w[Nb*r + c].to_bytes(4, "big") for c in range(Nb))
        rks.append(b)
    return rks

def _bytes_to_state(b: bytes) -> list[list[int]]:
    # column-major: state[row][col]
    return [[b[4*c + r] for c in range(4)] for r in range(4)]

def _state_to_bytes(s: list[list[int]]) -> bytes:
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4*c + r] = s[r][c] & 0xFF
    return bytes(out)

def _add_round_key(state, round_key: bytes):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[4*c + r]

def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def _inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def _shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def _inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def _mix_single_column(col):
    a0,a1,a2,a3 = col
    return [
        _gmul(a0,2) ^ _gmul(a1,3) ^ a2 ^ a3,
        a0 ^ _gmul(a1,2) ^ _gmul(a2,3) ^ a3,
        a0 ^ a1 ^ _gmul(a2,2) ^ _gmul(a3,3),
        _gmul(a0,3) ^ a1 ^ a2 ^ _gmul(a3,2)
    ]

def _inv_mix_single_column(col):
    a0,a1,a2,a3 = col
    return [
        _gmul(a0,14) ^ _gmul(a1,11) ^ _gmul(a2,13) ^ _gmul(a3,9),
        _gmul(a0,9)  ^ _gmul(a1,14) ^ _gmul(a2,11) ^ _gmul(a3,13),
        _gmul(a0,13) ^ _gmul(a1,9)  ^ _gmul(a2,14) ^ _gmul(a3,11),
        _gmul(a0,11) ^ _gmul(a1,13) ^ _gmul(a2,9)  ^ _gmul(a3,14)
    ]

def _mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        col = _mix_single_column(col)
        for r in range(4): state[r][c] = col[r]

def _inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        col = _inv_mix_single_column(col)
        for r in range(4): state[r][c] = col[r]

def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes (32 hex chars).")
    rks = _key_expansion(key)
    s = _bytes_to_state(block)
    _add_round_key(s, rks[0])
    for rnd in range(1, 10):
        _sub_bytes(s)
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, rks[rnd])
    _sub_bytes(s)
    _shift_rows(s)
    _add_round_key(s, rks[10])
    return _state_to_bytes(s)

def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes (32 hex chars).")
    rks = _key_expansion(key)
    s = _bytes_to_state(block)
    # Initial AddRoundKey with last round key
    _add_round_key(s, rks[10])
    # Rounds Nr-1 down to 1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
    for rnd in range(9, 0, -1):
        _inv_shift_rows(s)
        _inv_sub_bytes(s)
        _add_round_key(s, rks[rnd])
        _inv_mix_columns(s)
    # Final: InvShiftRows, InvSubBytes, AddRoundKey with round 0
    _inv_shift_rows(s)
    _inv_sub_bytes(s)
    _add_round_key(s, rks[0])
    return _state_to_bytes(s)

def encrypt_block_hex(plain_hex: str, key_hex: str) -> str:
    pt = bytes.fromhex(plain_hex.strip())
    k = bytes.fromhex(key_hex.strip())
    return encrypt_block(pt, k).hex().upper()

def decrypt_block_hex(cipher_hex: str, key_hex: str) -> str:
    ct = bytes.fromhex(cipher_hex.strip())
    k = bytes.fromhex(key_hex.strip())
    return decrypt_block(ct, k).hex().upper()    

if __name__ == "__main__":
    key_hex = input("Enter 32-hex AES-128 key: ").strip()
    block_hex = input("Enter 32-hex plaintext block: ").strip()
    if len(key_hex) != 32 or len(block_hex) != 32:
        print("Key and block must be 32 hex chars (16 bytes).")
        exit(1)
    ct = encrypt_block_hex(block_hex, key_hex)
    pt = decrypt_block_hex(ct, key_hex)
    print(f"Ciphertext: {ct}")
    print(f"Decrypted : {pt}")

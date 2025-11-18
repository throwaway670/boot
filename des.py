# Simple DES implementation (single 64-bit block, 16 rounds)
import random
random.seed(42)  # Fixed seed for reproducibility
IP = random.sample(range(1,65),64)
FP = [IP.index(i)+1 for i in range(1,65)]
# E must select 48 indices from 1..32 with repetition allowed
E = random.choices(range(1,33), k=48)
P = random.sample(range(1,33),32)
PC1 = random.sample(range(1,65),56)
PC2 = random.sample(range(1,57),48)
SHIFTS = random.choices([1,2],k=16)

SBOX = random.choices([[[random.randint(0,15) for _ in range(16)] for _ in range(4)] for _ in range(8)], k=8)

def _hex_to_bits(h):
    b = bin(int(h,16))[2:].zfill(len(h)*4)
    return [int(x) for x in b]

def _bits_to_hex(bits):
    return hex(int("".join(str(x) for x in bits),2))[2:].zfill(16).upper()

def _perm(bits, table):
    return [bits[i-1] for i in table]

def _lrot(bits, n):
    return bits[n:] + bits[:n]

def _split56(bits56):
    return bits56[:28], bits56[28:]

def _join_halves(l, r):
    return l + r

def _sbox_sub(bits48):
    out = []
    for i in range(8):
        chunk = bits48[6*i:6*i+6]
        row = (chunk[0]<<1) | chunk[5]
        col = (chunk[1]<<3) | (chunk[2]<<2) | (chunk[3]<<1) | chunk[4]
        val = SBOX[i][row][col]
        out.extend([(val>>3)&1,(val>>2)&1,(val>>1)&1,val&1])
    return out

def _f(r, k):
    er = _perm(r, E)
    xored = [a ^ b for a,b in zip(er, k)]
    sb = _sbox_sub(xored)
    return _perm(sb, P)

def _key_schedule(key_hex):
    key_bits = _hex_to_bits(key_hex)
    key56 = _perm(key_bits, PC1)
    c,d = _split56(key56)
    subkeys = []
    for s in SHIFTS:
        c = _lrot(c, s)
        d = _lrot(d, s)
        cd = _join_halves(c,d)
        subkeys.append(_perm(cd, PC2))
    return subkeys

def encrypt_block(block_hex, key_hex):
    bits = _hex_to_bits(block_hex)
    bits = _perm(bits, IP)
    l, r = bits[:32], bits[32:]
    subkeys = _key_schedule(key_hex)
    for k in subkeys:
        t = r
        r = [a ^ b for a,b in zip(l, _f(r, k))]
        l = t
    rl = r + l
    out = _perm(rl, FP)
    return _bits_to_hex(out)

def decrypt_block(block_hex, key_hex):
    bits = _hex_to_bits(block_hex)
    bits = _perm(bits, IP)
    l, r = bits[:32], bits[32:]
    subkeys = _key_schedule(key_hex)[::-1]
    for k in subkeys:
        t = r
        r = [a ^ b for a,b in zip(l, _f(r, k))]
        l = t
    rl = r + l
    out = _perm(rl, FP)
    return _bits_to_hex(out)   

if __name__ == "__main__":
    key = input("Enter 16-hex key (64-bit): ").strip()
    block = input("Enter 16-hex plaintext block (64-bit): ").strip()
    if len(key)!=16 or len(block)!=16:
        print("Key and block must be 16 hex chars.")
        exit(1)
    ct = encrypt_block(block, key)
    pt = decrypt_block(ct, key)
    print(f"Ciphertext: {ct}")
    print(f"Decrypted : {pt}")

# -----------------------
# Caesar Cipher
# -----------------------
from numpy import square


def encrypt_caesar(text, shift):
    shift %= 26
    res = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            res.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            res.append(ch)
    return "".join(res)

def decrypt_caesar(text, shift):
    return encrypt_caesar(text, -shift)

def main_caesar():
    text = input("Caesar | Enter text: ")
    shift = int(input("Caesar | Enter shift: "))
    enc = encrypt_caesar(text, shift)
    dec = decrypt_caesar(enc, shift)
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")

# def ceaser_enc(text, shift):
#     shift %= 26
#     res = []
#     for ch in text:
#         if ch.isalpha():
#             base = ord('A') if ch.isupper() else ord('a')
#             res.append(chr(((ord(ch)-base) + shift) %26 + base))
#         else:
#             res.append(ch)
#     return "".join(res)
# 
# def ceaser_dec(text, shift):
#     return ceaser_enc(text, -shift)

# -----------------------
# Monoalphabetic Substitution
# key: 26-letter permutation of A-Z (e.g., QWERTYUIOPASDFGHJKLZXCVBNM)
# -----------------------
def encrypt_substitution(text, key):
    key = key.upper()
    mp = {chr(ord('A') + i): key[i] for i in range(26)}
    res = []
    for ch in text:
        if ch.isalpha():
            up = ch.upper()
            sub = mp[up]
            res.append(sub if ch.isupper() else sub.lower())
        else:
            res.append(ch)
    return "".join(res)

def decrypt_substitution(text, key):
    key = key.upper()
    rmp = {key[i]: chr(ord('A') + i) for i in range(26)}
    res = []
    for ch in text:
        if ch.isalpha():
            up = ch.upper()
            sub = rmp[up]
            res.append(sub if ch.isupper() else sub.lower())
        else:
            res.append(ch)
    return "".join(res)

def main_monoalphabetic():
    text = input("Substitution | Enter text: ")
    key = input("Substitution | Enter 26-letter key: ")
    enc = encrypt_substitution(text, key)
    dec = decrypt_substitution(enc, key)
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")

# def mono_encrypt(text, key):
#     key = key.upper()
#     map = { chr(ord('A') + i): key[i] for i in range(26) }
#     res = []
#     for ch in text:
#         if ch.isalpha():
#             up = ch.upper()
#             sub = map[up]
#             res.append(sub if ch.isupper() else sub.lower())
#         else:
#             res.append(ch)
#     return "".join(res)

# def mono_decrypt(text, key):
#     key = key.upper()
#     reversemap = { key[i]: chr(ord('A') + i) for i in range(26) }
#     res = []
#     for ch in text:
#         if ch.isalpha():
#             up = ch.upper()
#             sub = reversemap[up]
#             res.append(sub if ch.isupper() else sub.lower())
#         else:
#             res.append(ch)
#     return "".join(res)

# -----------------------
# Vigenère Cipher
# -----------------------
def encrypt_vigenere(text, key):
    shifts = [ord(c.upper()) - ord('A') for c in key if c.isalpha()]
    if not shifts:
        return text
    res, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            s = shifts[j % len(shifts)]
            res.append(chr((ord(ch) - base + s) % 26 + base))
            j += 1
        else:
            res.append(ch)
    return "".join(res)

def decrypt_vigenere(text, key):
    shifts = [-(ord(c.upper()) - ord('A')) for c in key if c.isalpha()]
    if not shifts:
        return text
    res, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            s = shifts[j % len(shifts)]
            res.append(chr((ord(ch) - base + s) % 26 + base))
            j += 1
        else:
            res.append(ch)
    return "".join(res)

def main_vigenere():
    text = input("Vigenere | Enter text: ")
    key = input("Vigenere | Enter key: ")
    enc = encrypt_vigenere(text, key)
    dec = decrypt_vigenere(enc, key)
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")

# def vigenere_encrypt(text, key):
#     shifts = [ord(c.upper()) - ord('A') for c in key if c.isalpha()]
#     res = []
#     j = 0
#     for ch in text:
#         if ch.isalpha():
#             base = ord('A') if ch.isupper() else ord('a')
#             s = shifts[j % len(shifts)]
#             res.append(chr((ord(ch) - base + s) % 26 + base))
#             j += 1
#         else:
#             res.append(ch)
#     return "".join(res)

# def vigenere_decrypt(text, key):
#     shifts = [-(ord(c.upper()) - ord('A')) for c in key if c.isalpha()]
#     res = []
#     j = 0
#     for ch in text:
#         if ch.isalpha():
#             base = ord('A') if ch.isupper() else ord('a')
#             s = shifts[j % len(shifts)]
#             res.append(chr((ord(ch) - base + s) % 26 + base))
#             j += 1
#         else:
#             res.append(ch)
#     return "".join(res)

# -----------------------
# Playfair Cipher (simplified)
# -----------------------
def _pf_square(key):
    key = "".join(ch for ch in key.upper() if ch.isalpha()).replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    seen, seq = set(), []
    for ch in key + alphabet:
        if ch not in seen:
            seen.add(ch)
            seq.append(ch)
    square = [seq[i:i+5] for i in range(0, 25, 5)]
    pos = {square[r][c]: (r, c) for r in range(5) for c in range(5)}
    return square, pos

def _pf_pairs(text):
    s = "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")
    pairs, i = [], 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else None
        if b is None or a == b:
            pairs.append((a, "X"))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs

def encrypt_playfair(text, key):
    square, pos = _pf_square(key)
    out = []
    for a, b in _pf_pairs(text):
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            out.append(square[ra][(ca + 1) % 5])
            out.append(square[rb][(cb + 1) % 5])
        elif ca == cb:
            out.append(square[(ra + 1) % 5][ca])
            out.append(square[(rb + 1) % 5][cb])
        else:
            out.append(square[ra][cb])
            out.append(square[rb][ca])
    return "".join(out)

def decrypt_playfair(text, key):
    square, pos = _pf_square(key)
    s = "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")
    if len(s) % 2 == 1:
        s += "X"
    out = []
    for i in range(0, len(s), 2):
        a, b = s[i], s[i+1]
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            out.append(square[ra][(ca - 1) % 5])
            out.append(square[rb][(cb - 1) % 5])
        elif ca == cb:
            out.append(square[(ra - 1) % 5][ca])
            out.append(square[(rb - 1) % 5][cb])
        else:
            out.append(square[ra][cb])
            out.append(square[rb][ca])
    return "".join(out)

def main_playfair():
    text = input("Playfair | Enter text: ")
    key = input("Playfair | Enter key: ")
    enc = encrypt_playfair(text, key)
    dec = decrypt_playfair(enc, key)
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")

# def playfair_keygen(keyword):
#     keyword = "".join(ch for ch in keyword.upper() if ch.isalpha()).replace("J", "I")
#     alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
#     seen, seq = set(), []
    
#     for ch in keyword + alphabet:
#         if ch not in seen:
#             seen.add(ch)
#             seq.append(ch)
#     square = [seq[i:i+5] for i in range(0, 25, 5)]
#     pos = {square[r][c]: (r, c) for r in range(5) for c in range(5)}
#     return square, pos

# def playfair_pairmaker(text):
#     s = "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")
#     pairs, i = [], 0
#     while i < len(s):
#         a = s[i]
#         b = s[i+1] if i+1 < len(s) else None
#         if b is None or a == b:
#             pairs.append((a, "X"))
#             i += 1
#         else:
#             pairs.append((a, b))
#             i += 2
#     return pairs

# def playfair_encrypt(text, key):
#     square, pos = playfair_keygen(key)
#     out = []
#     for a, b in playfair_pairmaker(text):
#         ra, ca = pos[a]; rb, cb = pos[b]
#         if ra == rb:
#             out.append(square[ra][(ca + 1) % 5])
#             out.append(square[rb][(cb + 1) % 5])
#         elif ca == cb:
#             out.append(square[(ra + 1) % 5][ca])
#             out.append(square[(rb + 1) % 5][cb])
#         else:
#             out.append(square[ra][cb])
#             out.append(square[rb][ca])
#     return "".join(out)

# def playfair_decrypt(text, key):
#     square, pos = playfair_keygen(key)
#     s = "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")
#     if len(s) % 2 == 1:
#         s += "X"
#     out = []
#     for i in range(0, len(s), 2):
#         a, b = s[i], s[i+1]
#         ra, ca = pos[a]; rb, cb = pos[b]
#         if ra == rb:
#             out.append(square[ra][(ca - 1) % 5])
#             out.append(square[rb][(cb - 1) % 5])
#         elif ca == cb:
#             out.append(square[(ra - 1) % 5][ca])
#             out.append(square[(rb - 1) % 5][cb])
#         else:
#             out.append(square[ra][cb])
#             out.append(square[rb][ca])
#     return "".join(out)

# -----------------------
# Hill Cipher 2x2 (simplified)
# -----------------------
def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def _modinv(a, m):
    a %= m
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("Matrix not invertible modulo 26.")
    return x % m

def _inv2x2(K):
    a, b = K[0]
    c, d = K[1]
    a %= 26; b %= 26; c %= 26; d %= 26
    det = (a * d - b * c) % 26
    inv_det = _modinv(det, 26)
    return [
        [( d * inv_det) % 26, ((-b) * inv_det) % 26],
        [((-c) * inv_det) % 26, ( a * inv_det) % 26],
    ]

def _hill_pairs(text):
    nums = [ord(ch) - ord('A') for ch in text.upper() if ch.isalpha()]
    if len(nums) % 2 == 1:
        nums.append(ord('X') - ord('A'))
    return [nums[i:i+2] for i in range(0, len(nums), 2)]

def _mul2(K, v):
    return [
        (K[0][0]*v[0] + K[0][1]*v[1]) % 26,
        (K[1][0]*v[0] + K[1][1]*v[1]) % 26
    ]

def encrypt_hill(text, K):
    K = [[x % 26 for x in row] for row in K]
    out = []
    for v in _hill_pairs(text):
        out.extend(_mul2(K, v))
    return "".join(chr(n + ord('A')) for n in out)

def decrypt_hill(text, K):
    invK = _inv2x2(K)
    nums = [ord(ch) - ord('A') for ch in text.upper() if ch.isalpha()]
    if len(nums) % 2 == 1:
        nums.append(ord('X') - ord('A'))
    out = []
    for i in range(0, len(nums), 2):
        out.extend(_mul2(invK, nums[i:i+2]))
    return "".join(chr(n + ord('A')) for n in out)

def main_hill():
    text = input("Hill | Enter text: ")
    vals = list(map(int, input("Hill | Enter 4 integers (a b c d): ").split()))
    if len(vals) != 4:
        print("Need 4 integers.")
        return
    K = [[vals[0], vals[1]], [vals[2], vals[3]]]
    try:
        enc = encrypt_hill(text, K)
        dec = decrypt_hill(enc, K)
    except ValueError as e:
        print(str(e))
        return
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")

# def euc(a, b): # Extended Euclidean Algorithm with Modular Inverse
#     q = 0
#     r1, r2 = a, b
#     s1, s2 = 1, 0
#     t1, t2 = 0, 1
#     s, t = 0, 0
#     while r2 > 0:
#         q = r1 // r2
#         r = r1 - q * r2
#         r1, r2 = r2, r
        
#         s = s1 - q * s2
#         s1, s2 = s2, s
        
#         t = t1 - q * t2
#         t1, t2 = t2, t
    
#     if r1 == 1:
#         mi = s1 % b
#     else:
#         mi = None
#     return r1, s1, t1, mi

# def inv_matrix(mat, mod): # Inverse of 2x2 matrix modulo mod
#     det = (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % mod
#     g, x, y, inv_det = euc(det, mod)
#     if g != 1:
#         raise ValueError("Matrix not invertible modulo.")
#     inv_mat = [
#         [( mat[1][1] * inv_det) % mod, (-mat[0][1] * inv_det) % mod],
#         [(-mat[1][0] * inv_det) % mod, ( mat[0][0] * inv_det) % mod],
#     ]
#     return inv_mat

# def matrix_mult(K, v, mod): # Multiply 2x2 matrix K with 2x1 vector v modulo mod
#     res = [
#         (K[0][0]*v[0] + K[0][1]*v[1]) % mod,
#         (K[1][0]*v[0] + K[1][1]*v[1]) % mod
#     ]
#     return res

# def hill_pairs(text): # Convert text to list of number pairs
#     nums = [ord(ch) - ord('A') for ch in text.upper() if ch.isalpha()]
#     if len(nums) % 2 == 1:
#         nums.append(ord('X') - ord('A'))
#     return [nums[i:i+2] for i in range(0, len(nums), 2)]

# def hill_encrypt(text, K): # Hill cipher encryption
#     K = [[x % 26 for x in row] for row in K]
#     out = [] # Output list of numbers
#     for v in hill_pairs(text): # Process each pair
#         out.extend(matrix_mult(K, v, 26)) # Multiply with key matrix and append
#     return "".join(chr(n + ord('A')) for n in out) # Convert numbers back to letters

# def hill_decrypt(text, K): # Hill cipher decryption
#     invK = inv_matrix(K, 26) # Inverse key matrix modulo 26
#     nums = [ord(ch) - ord('A') for ch in text.upper() if ch.isalpha()] # Convert text to numbers
#     if len(nums) % 2 == 1:
#         nums.append(ord('X') - ord('A'))
#     out = []
#     for i in range(0, len(nums), 2):
#         out.extend(matrix_mult(invK, nums[i:i+2], 26)) # Multiply with inverse key matrix and append
#     return "".join(chr(n + ord('A')) for n in out) # Convert numbers back to letters
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a, m):
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse.")
    return x % m

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True

def generate_keys(p, q, e=None):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p and q must be prime.")
    if p == q:
        raise ValueError("p and q must be different.")
    n = p * q
    phi = (p - 1) * (q - 1)
    if e is None: # choose default e
        for cand in [65537, 3, 5, 17, 257]: # common choices for e
            if phi % cand != 0: # coprime with phi
                e = cand # select this e
                break
        else:
            e = 3 # fallback
            while e < phi and phi % e == 0: # find next coprime e
                e += 2
    if phi % e == 0:
        raise ValueError("e not coprime with phi. Choose another e.")
    d = modinv(e, phi) # private exponent
    return (n, e, d) # return public e and private d keys

def encrypt_int(m, n, e):
    if m < 0 or m >= n:
        raise ValueError("Message integer must be in range [0, n).")
    return pow(m, e, n) # encrypt m using RSA formula c = m^e mod n

def decrypt_int(c, n, d):
    return pow(c, d, n) # decrypt c using RSA formula m = c^d mod n

def encrypt_text(text, n, e): # encrypt each character as integer, text = string, n = modulus, e = public exponent
    if n <= 255:
        raise ValueError("n must be > 255 for text encryption.")
    return [pow(ord(ch), e, n) for ch in text]

def decrypt_text(cipher_list, n, d):
    return "".join(chr(pow(c, d, n)) for c in cipher_list)
 

if __name__ == "__main__":
    p = int(input("Enter prime p: "))
    q = int(input("Enter prime q: "))
    e_in = input("Enter public exponent e (blank for default): ").strip()
    e = int(e_in) if e_in else None
    try:
        n, e, d = generate_keys(p, q, e)
    except ValueError as err:
        print(err)
        exit(1)
    print(f"Public key (n, e): ({n}, {e})")
    print(f"Private key d: {d}")
    msg = input("Enter plaintext: ")
    try:
        cipher = encrypt_text(msg, n, e)
        print("Ciphertext (space-separated ints):")
        print(" ".join(map(str, cipher)))
        plain = decrypt_text(cipher, n, d)
        print(f"Decrypted: {plain}")
    except ValueError as err:
        print(err)
        exit(1)
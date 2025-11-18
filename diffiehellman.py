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

def dh_generate_public(p, g, private_key):
    return pow(g, private_key, p) # public key = g^private_key mod p

def dh_compute_shared(p, public_other, private_self):
    return pow(public_other, private_self, p)   # shared secret = public_other^private_self mod p  

if __name__ == "__main__":
    p = int(input("Enter prime modulus p: "))
    g = int(input("Enter base g (primitive root modulo p, try 2): "))
    if not is_prime(p) or p <= 2:
        print("p must be a prime > 2.")
        exit(1)
    if not (2 <= g <= p - 2):
        print("g must be in [2, p-2].")
        exit(1)

    a = int(input("Enter Alice's private key (a): "))
    b = int(input("Enter Bob's private key (b): "))

    A = dh_generate_public(p, g, a)  # Alice's public
    B = dh_generate_public(p, g, b)  # Bob's public

    s_alice = dh_compute_shared(p, B, a)
    s_bob = dh_compute_shared(p, A, b)

    print(f"Alice public A = {A}")
    print(f"Bob public   B = {B}")
    print(f"Shared secret (Alice) = {s_alice}")
    print(f"Shared secret (Bob)   = {s_bob}")
    if s_alice == s_bob:
        print("Success: Shared secrets match.")
    else:
        print("Error: Shared secrets do not match.")
        exit(1)
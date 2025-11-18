import os
import json
import hashlib
import random
from typing import Tuple


def egcd(a, b):
   if b == 0:
       return (a, 1, 0)
   g, x1, y1 = egcd(b, a % b)
   return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
   g, x, _ = egcd(a, m)
   if g != 1:
       raise ValueError("modular inverse does not exist")
   return x % m


def is_probable_prime(n, k=8):
   if n < 2:
       return False
   small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
   for p in small_primes:
       if n % p == 0:
           return n == p
   d = n - 1
   s = 0
   while d % 2 == 0:
       s += 1
       d //= 2
   for _ in range(k):
       a = random.randrange(2, n - 2)
       x = pow(a, d, n)
       if x == 1 or x == n - 1:
           continue
       for _ in range(s - 1):
           x = pow(x, 2, n)
           if x == n - 1:
               break
       else:
           return False
   return True


def gen_prime(bits: int) -> int:
   while True:
       cand = random.getrandbits(bits) | 1 | (1 << (bits - 1))
       if is_probable_prime(cand):
           return cand


def rsa_keygen(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
   e = 65537
   while True:
       p = gen_prime(bits // 2)
       q = gen_prime(bits // 2)
       if p == q:
           continue
       n = p * q
       phi = (p - 1) * (q - 1)
       if phi % e == 0:
           continue
       d = modinv(e, phi)
       return (n, e), (n, d)


def rsa_encrypt_bytes(pubkey: Tuple[int, int], data: bytes) -> int:
   n, e = pubkey
   m = int.from_bytes(data, 'big')
   if m >= n:
       raise ValueError("Message too large for RSA modulus")
   return pow(m, e, n)


def rsa_decrypt_to_bytes(privkey: Tuple[int, int], c: int) -> bytes:
   n, d = privkey
   m = pow(c, d, n)
   length = (m.bit_length() + 7) // 8
   return m.to_bytes(length, 'big')


def keystream(key: bytes, length: int) -> bytes:
   out = bytearray()
   counter = 0
   while len(out) < length:
       h = hashlib.sha256(key + counter.to_bytes(8, 'big')).digest()
       out.extend(h)
       counter += 1
   return bytes(out[:length])


def sxor(key: bytes, data: bytes) -> bytes:
   ks = keystream(key, len(data))
   return bytes(a ^ b for a, b in zip(ks, data))


def sym_encrypt(key: bytes, plaintext: bytes) -> bytes:
   return sxor(key, plaintext)


def sym_decrypt(key: bytes, ciphertext: bytes) -> bytes:
   return sxor(key, ciphertext)


def pubkey_to_dict(pubkey: Tuple[int, int]):
   n, e = pubkey
   return {"n": str(n), "e": e}


def dict_to_pubkey(d):
   return (int(d["n"]), int(d["e"]))

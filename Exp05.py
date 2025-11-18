import os, sys, time, math, random, struct
from typing import Tuple
from dataclasses import dataclass




SBOX = [
   # 0     1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
   0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
   0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
   0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
   0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
   0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
   0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
   0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
   0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
   0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
   0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
   0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
   0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
   0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
   0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
   0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
   0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]




INV_SBOX = [0]*256
for i,v in enumerate(SBOX):
   INV_SBOX[v] = i




RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]




def xtime(byte):
   return ((byte << 1) ^ 0x1B) & 0xFF if (byte & 0x80) else (byte << 1) & 0xFF




def mul(a,b):
   # Multiply two bytes in GF(2^8)
   res = 0
   for i in range(8):
       if b & 1:
           res ^= a
       hi_bit = a & 0x80
       a = (a << 1) & 0xFF
       if hi_bit:
           a ^= 0x1B
       b >>= 1
   return res & 0xFF




def sub_word(word):
   return [SBOX[b] for b in word]




def rot_word(word):
   return word[1:] + word[:1]




def key_expansion(key: bytes):
   # AES-128 key schedule: 16-byte key -> 176-byte expanded key (44 words)
   assert len(key) == 16
   Nk = 4
   Nb = 4
   Nr = 10
   w = [list(key[i:i+4]) for i in range(0, 16, 4)]
   for i in range(Nk, Nb*(Nr+1)):
       temp = w[i-1].copy()
       if i % Nk == 0:
           temp = sub_word(rot_word(temp))
           temp[0] ^= RCON[i//Nk]
       w.append([ (w[i-Nk][j] ^ temp[j]) & 0xFF for j in range(4) ])
   # flatten to bytes
   expanded = b''.join(bytes(word) for word in w)
   return expanded  # 176 bytes




def add_round_key(state, round_key):
   return [s ^ k for s,k in zip(state, round_key)]




def sub_bytes(state):
   return [SBOX[b] for b in state]




def inv_sub_bytes(state):
   return [INV_SBOX[b] for b in state]




def shift_rows(state):
   # state is 16 bytes in column-major order
   out = [0]*16
   # row 0: no shift
   out[0] = state[0]; out[4]=state[4]; out[8]=state[8]; out[12]=state[12]
   # row1: shift left by 1
   out[1] = state[5]; out[5]=state[9]; out[9]=state[13]; out[13]=state[1]
   # row2: shift left by 2
   out[2] = state[10]; out[6]=state[14]; out[10]=state[2]; out[14]=state[6]
   # row3: shift left by 3
   out[3]=state[15]; out[7]=state[3]; out[11]=state[7]; out[15]=state[11]
   return out




def inv_shift_rows(state):
   out = [0]*16
   out[0]=state[0]; out[4]=state[4]; out[8]=state[8]; out[12]=state[12]
   out[1]=state[13]; out[5]=state[1]; out[9]=state[5]; out[13]=state[9]
   out[2]=state[10]; out[6]=state[14]; out[10]=state[2]; out[14]=state[6]
   out[3]=state[7]; out[7]=state[11]; out[11]=state[15]; out[15]=state[3]
   return out




def mix_single_column(a):
   # a is 4-byte column
   r = [
       (mul(a[0],2) ^ mul(a[1],3) ^ a[2] ^ a[3]) & 0xFF,
       (a[0] ^ mul(a[1],2) ^ mul(a[2],3) ^ a[3]) & 0xFF,
       (a[0] ^ a[1] ^ mul(a[2],2) ^ mul(a[3],3)) & 0xFF,
       (mul(a[0],3) ^ a[1] ^ a[2] ^ mul(a[3],2)) & 0xFF
   ]
   return r




def mix_columns(state):
   out = [0]*16
   for c in range(4):
       col = [ state[r + 4*c] for r in range(4) ]
       mixed = mix_single_column(col)
       for r in range(4):
           out[r + 4*c] = mixed[r]
   return out




def inv_mix_columns(state):
   out = [0]*16
   for c in range(4):
       col = [ state[r + 4*c] for r in range(4) ]
       r0 = (mul(col[0],14) ^ mul(col[1],11) ^ mul(col[2],13) ^ mul(col[3],9)) & 0xFF
       r1 = (mul(col[0],9) ^ mul(col[1],14) ^ mul(col[2],11) ^ mul(col[3],13)) & 0xFF
       r2 = (mul(col[0],13) ^ mul(col[1],9) ^ mul(col[2],14) ^ mul(col[3],11)) & 0xFF
       r3 = (mul(col[0],11) ^ mul(col[1],13) ^ mul(col[2],9) ^ mul(col[3],14)) & 0xFF
       out[0 + 4*c] = r0; out[1 + 4*c] = r1; out[2 + 4*c] = r2; out[3 + 4*c] = r3
   return out




def bytes_to_state(block: bytes):
   # AES state is column-major
   assert len(block) == 16
   return list(block)




def state_to_bytes(state):
   return bytes(state)




def aes_encrypt_block(block: bytes, expanded_key: bytes):
   state = bytes_to_state(block)
   Nb = 4; Nr = 10
   # initial AddRoundKey
   round_key = expanded_key[0:16]
   state = add_round_key(state, list(round_key))
   for rnd in range(1, Nr):
       state = sub_bytes(state)
       state = shift_rows(state)
       state = mix_columns(state)
       round_key = expanded_key[16*rnd:16*(rnd+1)]
       state = add_round_key(state, list(round_key))
   # final round
   state = sub_bytes(state)
   state = shift_rows(state)
   round_key = expanded_key[16*Nr:16*(Nr+1)]
   state = add_round_key(state, list(round_key))
   return state_to_bytes(state)




def aes_decrypt_block(block: bytes, expanded_key: bytes):
   state = bytes_to_state(block)
   Nr = 10
   # initial AddRoundKey with last round key
   round_key = expanded_key[16*Nr:16*(Nr+1)]
   state = add_round_key(state, list(round_key))
   for rnd in range(Nr-1,0,-1):
       state = inv_shift_rows(state)
       state = inv_sub_bytes(state)
       round_key = expanded_key[16*rnd:16*(rnd+1)]
       state = add_round_key(state, list(round_key))
       state = inv_mix_columns(state)
   # final
   state = inv_shift_rows(state)
   state = inv_sub_bytes(state)
   round_key = expanded_key[0:16]
   state = add_round_key(state, list(round_key))
   return state_to_bytes(state)




# PKCS7 padding helpers
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
   pad_len = block_size - (len(data) % block_size)
   return data + bytes([pad_len])*pad_len




def pkcs7_unpad(data: bytes) -> bytes:
   if not data:
       raise ValueError("Invalid padding (empty)!")
   pad_len = data[-1]
   if pad_len < 1 or pad_len > 16:
       raise ValueError("Invalid padding length")
   if data[-pad_len:] != bytes([pad_len])*pad_len:
       raise ValueError("Invalid PKCS7 padding bytes")
   return data[:-pad_len]




# Mode operations
def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> Tuple[bytes,float]:
   if len(key) != 16:
       raise ValueError("AES-128 requires 16-byte key")
   expanded = key_expansion(key)
   padded = pkcs7_pad(plaintext, 16)
   ct = bytearray()
   t0 = time.perf_counter()
   for i in range(0,len(padded),16):
       blk = padded[i:i+16]
       ct_blk = aes_encrypt_block(blk, expanded)
       ct.extend(ct_blk)
   t = time.perf_counter() - t0
   return bytes(ct), t




def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> Tuple[bytes,float]:
   if len(key) != 16:
       raise ValueError("AES-128 requires 16-byte key")
   expanded = key_expansion(key)
   pt = bytearray()
   t0 = time.perf_counter()
   for i in range(0,len(ciphertext),16):
       blk = ciphertext[i:i+16]
       pt_blk = aes_decrypt_block(blk, expanded)
       pt.extend(pt_blk)
   t = time.perf_counter() - t0
   return pkcs7_unpad(bytes(pt)), t




def aes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> Tuple[bytes,float]:
   if len(iv)!=16:
       raise ValueError("IV must be 16 bytes")
   expanded = key_expansion(key)
   padded = pkcs7_pad(plaintext,16)
   ct = bytearray()
   prev = iv
   t0 = time.perf_counter()
   for i in range(0,len(padded),16):
       blk = padded[i:i+16]
       xored = bytes(a^b for a,b in zip(blk, prev))
       ct_blk = aes_encrypt_block(xored, expanded)
       ct.extend(ct_blk)
       prev = ct_blk
   t = time.perf_counter() - t0
   return bytes(ct), t




def aes_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> Tuple[bytes,float]:
   if len(iv)!=16:
       raise ValueError("IV must be 16 bytes")
   expanded = key_expansion(key)
   pt = bytearray()
   prev = iv
   t0 = time.perf_counter()
   for i in range(0,len(ciphertext),16):
       blk = ciphertext[i:i+16]
       dec_blk = aes_decrypt_block(blk, expanded)
       plain_blk = bytes(a^b for a,b in zip(dec_blk, prev))
       pt.extend(plain_blk)
       prev = blk
   t = time.perf_counter() - t0
   return pkcs7_unpad(bytes(pt)), t




# ---------------- RSA Implementation (educational) --------------------------
# Miller-Rabin primality and key generation
def is_probable_prime(n:int, k:int=8) -> bool:
   if n < 2:
       return False
   small_primes = [2,3,5,7,11,13,17,19,23,29]
   for p in small_primes:
       if n % p == 0:
           return n == p
   # write n-1 as d*2^s
   s = 0
   d = n-1
   while d % 2 == 0:
       d //= 2; s += 1
   for _ in range(k):
       a = random.randrange(2, n-1)
       x = pow(a, d, n)
       if x==1 or x==n-1:
           continue
       for __ in range(s-1):
           x = pow(x, 2, n)
           if x==n-1:
               break
       else:
           return False
   return True




def generate_prime(bits:int) -> int:
   assert bits >= 16
   while True:
       candidate = random.getrandbits(bits) | (1 << (bits-1)) | 1
       if is_probable_prime(candidate):
           return candidate




def egcd(a:int,b:int):
   if b==0:
       return (a,1,0)
   g,x1,y1 = egcd(b, a%b)
   return (g, y1, x1 - (a//b)*y1)




def modinv(a:int, m:int):
   g,x,y = egcd(a,m)
   if g != 1:
       raise ValueError("No modular inverse")
   return x % m




def rsa_generate_keypair(bits:int=1024) -> Tuple[Tuple[int,int], Tuple[int,int]]:
   # generate two primes p and q
   p = generate_prime(bits//2)
   q = generate_prime(bits//2)
   while q == p:
       q = generate_prime(bits//2)
   n = p*q
   phi = (p-1)*(q-1)
   e = 65537
   if math.gcd(e, phi) != 1:
       # pick another e small
       e = 3
       while math.gcd(e, phi) != 1:
           e += 2
   d = modinv(e, phi)
   return (n,e), (n,d)




# PKCS#1 v1.5 padding for encryption (simple)
def pkcs1_v1_5_pad(message: bytes, k: int) -> bytes:
   # k = length of modulus in bytes
   # For encryption: 0x00 || 0x02 || PS || 0x00 || M, PS must be non-zero random bytes, len(PS) >= 8
   mlen = len(message)
   if mlen > k - 11:
       raise ValueError("Message too long for RSA modulus")
   ps_len = k - mlen - 3
   ps = b''
   while len(ps) < ps_len:
       rb = random.randint(1,255)
       ps += bytes([rb])
   return b'\x00\x02' + ps + b'\x00' + message




def pkcs1_v1_5_unpad(padded: bytes) -> bytes:
   if len(padded) < 11:
       raise ValueError("Decryption error")
   if padded[0:2] != b'\x00\x02':
       raise ValueError("Decryption error (invalid padding)")
   # find 0x00 separator
   try:
       sep = padded.index(b'\x00', 2)
   except ValueError:
       raise ValueError("Decryption error (no separator)")
   return padded[sep+1:]




def rsa_encrypt(message: bytes, pubkey: Tuple[int,int]) -> Tuple[int, float]:
   n,e = pubkey
   k = (n.bit_length()+7)//8
   padded = pkcs1_v1_5_pad(message, k)
   m = int.from_bytes(padded, 'big')
   t0 = time.perf_counter()
   c = pow(m, e, n)
   t = time.perf_counter() - t0
   return c, t




def rsa_decrypt(cipher_int: int, privkey: Tuple[int,int]) -> Tuple[bytes, float]:
   n,d = privkey
   t0 = time.perf_counter()
   m = pow(cipher_int, d, n)
   t = time.perf_counter() - t0
   k = (n.bit_length()+7)//8
   padded = m.to_bytes(k, 'big')
   message = pkcs1_v1_5_unpad(padded)
   return message, t




# helpers to convert ints/bytes
def int_to_bytes(i:int) -> bytes:
   return i.to_bytes((i.bit_length()+7)//8, 'big') or b'\x00'




def bytes_to_int(b:bytes) -> int:
   return int.from_bytes(b, 'big')




# ---------------- Hybrid (AES session key encrypted by RSA) -----------------
@dataclass
class PerfEntry:
   name: str
   size_bytes: int
   aes_mode: str
   aes_enc_time: float
   aes_dec_time: float
   rsa_enc_time: float
   rsa_dec_time: float
   hybrid_enc_time: float
   hybrid_dec_time: float




# ---------------- Menu & I/O ------------------------------------------------
def hexify(b: bytes) -> str:
   return b.hex()




def run_aes_interactive():
   print("AES-128 (ECB/CBC)")
   mode = input("Mode (ECB/CBC) [ECB]: ").strip().upper() or "ECB"
   key_in = input("Enter 16-char key (leave blank to generate random): ")
   if not key_in:
       key = os.urandom(16)
       print("Generated key (hex):", key.hex())
   else:
       if len(key_in) != 16:
           print("Key length not 16 -> trimming/padding")
           key = key_in.encode('utf-8')[:16].ljust(16,b'\x00')
       else:
           key = key_in.encode('utf-8')
   text = input("Enter plaintext: ").encode('utf-8')
   if mode == "ECB":
       ct,enc_t = aes_encrypt_ecb(text, key)
       pt,dec_t = aes_decrypt_ecb(ct, key)
       print("Ciphertext (hex):", ct.hex())
       print("Decrypted plaintext:", pt.decode('utf-8'))
   else:
       iv = os.urandom(16)
       ct,enc_t = aes_encrypt_cbc(text, key, iv)
       pt,dec_t = aes_decrypt_cbc(ct, key, iv)
       print("IV (hex):", iv.hex())
       print("Ciphertext (hex):", ct.hex())
       print("Decrypted plaintext:", pt.decode('utf-8'))
   print(f"AES enc time: {enc_t:.6f}s, dec time: {dec_t:.6f}s")




def run_rsa_interactive():
   bits = input("RSA key size in bits [1024]: ").strip() or "1024"
   bits = int(bits)
   pub, priv = rsa_generate_keypair(bits)
   n,e = pub; n2,d = priv
   print(f"Public key n (bits={n.bit_length()}): {n}\ne: {e}")
   print("Private d:", d)
   msg = input("Enter plaintext: ").encode('utf-8')
   c, enc_t = rsa_encrypt(msg, pub)
   print("Ciphertext (int):", c)
   recovered, dec_t = rsa_decrypt(c, priv)
   print("Recovered plaintext:", recovered.decode('utf-8'))
   print(f"RSA enc time: {enc_t:.6f}s, dec time: {dec_t:.6f}s")




def run_hybrid_interactive():
   print("Hybrid system: RSA for AES key, AES-128 for message")
   bits = int(input("RSA bits [1024]: ") or "1024")
   pub, priv = rsa_generate_keypair(bits)
   n,e = pub
   key = os.urandom(16)  # AES-128 session key
   msg = input("Enter plaintext: ").encode('utf-8')
   # AES encrypt (CBC)
   iv = os.urandom(16)
   aes_ct, aes_enc_t = aes_encrypt_cbc(msg, key, iv)
   # RSA encrypt AES key
   c_key, rsa_enc_t = rsa_encrypt(key, pub)
   # Demonstrate recovery
   recovered_key, rsa_dec_t = rsa_decrypt(c_key, priv)
   recovered_msg, aes_dec_t = aes_decrypt_cbc(aes_ct, recovered_key, iv)
   print("AES ciphertext (hex):", aes_ct.hex())
   print("Encrypted AES key (int):", c_key)
   print("Recovered message:", recovered_msg.decode('utf-8'))
   print(f"AES enc time: {aes_enc_t:.6f}s, AES dec time: {aes_dec_t:.6f}s")
   print(f"RSA key enc time: {rsa_enc_t:.6f}s, RSA key dec time: {rsa_dec_t:.6f}s")




def perform_performance_tests(output_filename="crypto_io_results.txt"):
   sizes = [1024, 10*1024, 50*1024]  # 1KB, 10KB, 50KB
   aes_modes = ["ECB","CBC"]
   bits = 1024  # RSA keysize for tests
   pub, priv = rsa_generate_keypair(bits)
   results = []
   with open(output_filename, "w") as f:
       f.write("=== Performance Tests: AES-128 (ECB/CBC), RSA (key encryption), Hybrid ===\n")
       f.write(f"RSA bits: {bits}\n\n")
       for size in sizes:
           f.write(f"--- Message size: {size} bytes ({size/1024:.2f} KB) ---\n")
           plaintext = os.urandom(size)
           for mode in aes_modes:
               key = os.urandom(16)
               if mode == "ECB":
                   ct, enc_t = aes_encrypt_ecb(plaintext, key)
                   pt, dec_t = aes_decrypt_ecb(ct, key)
               else:
                   iv = os.urandom(16)
                   ct, enc_t = aes_encrypt_cbc(plaintext, key, iv)
                   pt, dec_t = aes_decrypt_cbc(ct, key, iv)
               f.write(f"AES {mode} | enc_time: {enc_t:.6f}s | dec_time: {dec_t:.6f}s | ciphertext_len: {len(ct)} bytes\n")
               # Pure RSA for the whole message (note: will fail if message longer than modulus-11)
               k_bytes = (pub[0].bit_length()+7)//8
               can_rsa = (len(plaintext) <= k_bytes - 11)
               if can_rsa:
                   c_full, r_enc = rsa_encrypt(plaintext, pub)
                   rec, r_dec = rsa_decrypt(c_full, priv)
                   f.write(f"RSA direct | enc_time: {r_enc:.6f}s | dec_time: {r_dec:.6f}s | cipher_int_size: {c_full.bit_length()} bits\n")
               else:
                   f.write(f"RSA direct | SKIPPED (message too large for RSA modulus of {k_bytes} bytes)\n")
               # Hybrid: AES session key + AES data
               # AES part:
               key_sess = os.urandom(16)
               iv2 = os.urandom(16)
               aes_ct2, aes_enc_t = aes_encrypt_cbc(plaintext, key_sess, iv2)
               # RSA encrypt session key
               ckey, rsa_e_t = rsa_encrypt(key_sess, pub)
               # RSA decrypt session key
               recovered_k, rsa_d_t = rsa_decrypt(ckey, priv)
               # AES decrypt
               recovered_pt, aes_d_t = aes_decrypt_cbc(aes_ct2, recovered_k, iv2)
               assert recovered_pt == plaintext
               f.write(f"Hybrid | AES enc: {aes_enc_t:.6f}s AES dec: {aes_d_t:.6f}s | RSA key enc: {rsa_e_t:.6f}s RSA key dec: {rsa_d_t:.6f}s | total_cipher_len: {len(aes_ct2)} bytes\n")
           f.write("\n")
   print(f"Performance tests written to {output_filename}")




def menu():
   print("")
   print("Menu:")
   print("1) AES Encryption/Decryption")
   print("2) RSA Encryption/Decryption")
   print("3) Hybrid System")
   print("4) Performance Comparison (writes crypto_io_results.txt)")
   print("5) Quit")




def main():
   while True:
       menu()
       ch = input("Choose option (1-5): ").strip()
       if ch == '1':
           run_aes_interactive()
       elif ch == '2':
           run_rsa_interactive()
       elif ch == '3':
           run_hybrid_interactive()
       elif ch == '4':
           fname = input("Enter output filename [crypto_io_results.txt]: ").strip() or "crypto_io_results.txt"
           perform_performance_tests(fname)
       elif ch == '5':
           print("Exiting.")
           break
       else:
           print("Invalid choice.")




if __name__ == "__main__":
   main()
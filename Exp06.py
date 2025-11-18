import sys
import time
import math
import random
import struct
import hashlib
from typing import List, Tuple






MASK32 = 0xFFFFFFFF




def rotr(x: int, n: int) -> int:
  """Right rotate 32-bit integer x by n bits."""
  return ((x >> n) | ((x << (32 - n)) & MASK32)) & MASK32




def shr(x: int, n: int) -> int:
  return (x >> n) & MASK32




def ch(x: int, y: int, z: int) -> int:
  return (x & y) ^ (~x & z)




def maj(x: int, y: int, z: int) -> int:
  return (x & y) ^ (x & z) ^ (y & z)




# big sigma and small sigma functions for SHA-256
def big_sigma0(x): return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
def big_sigma1(x): return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
def small_sigma0(x): return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
def small_sigma1(x): return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)




# SHA-256 round constants (first 32 bits of cube roots of first 64 primes)
K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]




def sha256_bytes(message: bytes) -> bytes:
  """Compute SHA-256 hash of a byte string (returns raw 32 bytes)."""
  # 1) Preprocessing: padding
  ml = len(message) * 8  # message length in bits
  # append '1' bit (0x80), then zero bytes until length ≡ 448 mod 512, then 64-bit big-endian length
  padded = bytearray(message)
  padded.append(0x80)
  # pad with zeros until (len in bytes) % 64 == 56
  while (len(padded) % 64) != 56:
      padded.append(0x00)
  padded += struct.pack('>Q', ml)




  # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
  H = [
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19
  ]




  # process each 512-bit block
  for block_start in range(0, len(padded), 64):
      block = padded[block_start:block_start+64]
      # 2) Prepare message schedule W[0..63]
      W = [0]*64
      # first 16 words are from the block
      for t in range(16):
          W[t] = struct.unpack('>I', block[t*4:(t+1)*4])[0]
      for t in range(16, 64):
          s0 = small_sigma0(W[t-15])
          s1 = small_sigma1(W[t-2])
          W[t] = (W[t-16] + s0 + W[t-7] + s1) & MASK32




      # 3) Initialize working variables a..h
      a,b,c,d,e,f,g,h = H




      # 4) Main loop
      for t in range(64):
          T1 = (h + big_sigma1(e) + ch(e,f,g) + K[t] + W[t]) & MASK32
          T2 = (big_sigma0(a) + maj(a,b,c)) & MASK32
          h = g
          g = f
          f = e
          e = (d + T1) & MASK32
          d = c
          c = b
          b = a
          a = (T1 + T2) & MASK32




      # 5) Compute intermediate hash value
      H = [
          (H[0] + a) & MASK32,
          (H[1] + b) & MASK32,
          (H[2] + c) & MASK32,
          (H[3] + d) & MASK32,
          (H[4] + e) & MASK32,
          (H[5] + f) & MASK32,
          (H[6] + g) & MASK32,
          (H[7] + h) & MASK32,
      ]




  # produce final hash (big-endian)
  out = b''.join(struct.pack('>I', h) for h in H)
  return out




def sha256_hex(message: bytes) -> str:
  return sha256_bytes(message).hex()




# convenience wrapper for string input
def sha256_of_string(s: str) -> str:
  return sha256_hex(s.encode('utf-8'))




# ---------------------------
# Merkle Tree implementation
# ---------------------------
class MerkleTree:
  def __init__(self, leaves: List[bytes]):
      """
      leaves: list of byte-strings (raw data). We'll hash each leaf using our SHA-256 implementation.
      """
      self.leaves_data = leaves[:]
      self.leaves_hashes = [sha256_bytes(ld) for ld in leaves]
      self.levels = []  # bottom-up: levels[0] = leaf hashes, levels[-1] = root
      self.build_tree()




  def build_tree(self):
      cur = self.leaves_hashes[:]
      self.levels = [cur]
      while len(cur) > 1:
          nxt = []
          for i in range(0, len(cur), 2):
              left = cur[i]
              if i+1 < len(cur):
                  right = cur[i+1]
              else:
                  # duplicate last if odd
                  right = left
              parent = sha256_bytes(left + right)
              nxt.append(parent)
          cur = nxt
          self.levels.append(cur)




  def root(self) -> bytes:
      return self.levels[-1][0] if self.levels and self.levels[-1] else b''




  def get_proof(self, index: int) -> List[Tuple[bytes, str]]:
      """
      Returns a list of (sibling_hash, 'L'/'R') pairs representing the authentication path
      where 'L' means sibling is left of current node, 'R' means right.
      """
      proof = []
      idx = index
      for level in range(len(self.levels)-1):
          level_nodes = self.levels[level]
          sibling_index = idx ^ 1  # toggle last bit
          if sibling_index < len(level_nodes):
              sibling = level_nodes[sibling_index]
              side = 'L' if sibling_index < idx else 'R'
              proof.append((sibling, side))
          else:
              # no sibling, treat as duplicate of node
              sibling = level_nodes[idx]
              side = 'L'  # arbitrary
              proof.append((sibling, side))
          idx //= 2
      return proof




  @staticmethod
  def verify_proof(leaf_data: bytes, proof: List[Tuple[bytes, str]], root: bytes) -> bool:
      cur = sha256_bytes(leaf_data)
      for sibling_hash, side in proof:
          if side == 'L':
              cur = sha256_bytes(sibling_hash + cur)
          else:
              cur = sha256_bytes(cur + sibling_hash)
      return cur == root




# ---------------------------
# Security tests
# ---------------------------
def hamming_distance_bytes(a: bytes, b: bytes) -> int:
  """Compute Hamming distance (number of differing bits) between two equal-length byte strings."""
  if len(a) != len(b):
      raise ValueError("Lengths differ for Hamming distance")
  dist = 0
  for x,y in zip(a, b):
      dist += bin(x ^ y).count("1")
  return dist




def avalanche_test(trials: int = 200) -> None:
  """Change one random bit in random message and measure bit flips in hash."""
  print(f"\nAvalanche test: {trials} trials")
  distances = []
  for _ in range(trials):
      # random length between 1 and 128 bytes
      L = random.randint(1, 128)
      msg = bytearray(random.getrandbits(8) for _ in range(L))
      # choose a random bit to flip
      bit_index = random.randint(0, L*8 - 1)
      byte_index = bit_index // 8
      bit_in_byte = bit_index % 8
      msg2 = bytearray(msg)
      msg2[byte_index] ^= (1 << bit_in_byte)
      h1 = sha256_bytes(bytes(msg))
      h2 = sha256_bytes(bytes(msg2))
      d = hamming_distance_bytes(h1, h2)
      distances.append(d)
  avg = sum(distances)/len(distances)
  mn = min(distances)
  mx = max(distances)
  print(f"Results (bits flipped vs 256): avg={avg:.2f}, min={mn}, max={mx}")
  print("Ideal average for a 256-bit hash is ~128 (half the bits).")




def distribution_analysis(samples: int = 2000) -> None:
  """Collect many outputs and compute per-bit frequency of '1's."""
  print(f"\nDistribution analysis: {samples} random messages")
  bit_counts = [0]*256
  for _ in range(samples):
      L = random.randint(1, 64)
      msg = bytes(random.getrandbits(8) for _ in range(L))
      h = sha256_bytes(msg)
      # count bit ones
      for i, byte in enumerate(h):
          for b in range(8):
              if (byte >> (7-b)) & 1:
                  bit_counts[i*8 + b] += 1
  # compute percent ones per bit
  freqs = [c / samples for c in bit_counts]
  # summary statistics
  avg = sum(freqs)/len(freqs)
  deviations = [abs(f - 0.5) for f in freqs]
  max_dev = max(deviations)
  print(f"Average fraction of 1-bits across positions: {avg:.4f} (ideal 0.5)")
  print(f"Maximum deviation from 0.5 for any bit position: {max_dev:.4f}")
  print("Example per-bit frequencies (first 16 bits):")
  for i in range(16):
      print(f" bit {i:03d}: {freqs[i]:.4f}", end=(";" if i%4!=3 else "\n"))
  print("A well-distributed hash should have frequencies close to 0.5 for each bit.")




def birthday_collision_search(trunc_bits: int = 32, max_iters: int = 200000) -> None:
  """
  Search for a collision on the truncated hash of length trunc_bits using birthday method.
  Important: Full 256-bit collision search is infeasible; we use truncation to demonstrate method.
  """
  if trunc_bits <= 0 or trunc_bits > 256:
      raise ValueError("trunc_bits must be 1..256")
  print(f"\nBirthday attack simulation (truncate to {trunc_bits} bits). Max attempts: {max_iters}")
  seen = {}
  mask = (1 << trunc_bits) - 1
  for i in range(max_iters):
      # generate a random message (random bytes)
      L = random.randint(1, 64)
      msg = bytes(random.getrandbits(8) for _ in range(L))
      h = sha256_bytes(msg)
      # take first trunc_bits of hash (big-endian)
      # create integer from first 4 or 8 bytes as needed
      # easiest: take integer of full hash and mask high-order bits
      h_int = int.from_bytes(h, 'big') >> (256 - trunc_bits)
      if h_int in seen:
          msg0 = seen[h_int]
          if msg0 != msg:
              print(f"Collision found after {i+1} attempts!")
              print(f" Truncated hash (hex, {trunc_bits} bits): {h_int:0{(trunc_bits+3)//4}x}")
              print(f" Message A (len {len(msg0)}): {msg0.hex()[:80]}...")
              print(f" Message B (len {len(msg)}): {msg.hex()[:80]}...")
              return
      else:
          seen[h_int] = msg
  print("No collision found within limit. Increase max_iters or reduce trunc_bits to make collision more likely.")




def performance_benchmark(sizes_bytes = [16, 64, 256, 1024, 8192, 65536]) -> None:
  """Time SHA-256 on different input sizes."""
  print("\nPerformance benchmarking (average of 10 runs per size):")
  for sz in sizes_bytes:
      trials = 10
      data = bytes(random.getrandbits(8) for _ in range(sz))
      t0 = time.perf_counter()
      for _ in range(trials):
          _ = sha256_bytes(data)
      t1 = time.perf_counter()
      avg_time_ms = (t1 - t0) / trials * 1000.0
      print(f" size={sz:6d} bytes -> avg {avg_time_ms:.3f} ms per hash")




def comparative_analysis_example(s: str = "The quick brown fox") -> None:
  """Compare SHA-256 (ours) with hashlib MD5 and SHA1 for demonstration."""
  print("\nComparative analysis (example hash outputs):")
  b = s.encode('utf-8')
  our = sha256_hex(b)
  md5 = hashlib.md5(b).hexdigest()
  sha1 = hashlib.sha1(b).hexdigest()
  print(f" Input: {s!r}")
  print(f" SHA-256 (this implementation) : {our}")
  print(f" MD5 (hashlib)                : {md5}")
  print(f" SHA-1 (hashlib)              : {sha1}")
  print("\nSecurity notes (summary):")
  print(" - MD5: broken (collisions easily found); NOT recommended for security.")
  print(" - SHA-1: collision attacks exist (practical in recent years); NOT recommended for collision resistance.")
  print(" - SHA-256: currently considered secure against collisions and preimage attacks for practical use (256-bit output).")
  print(" - Length-extension attacks: SHA-256 (Merkle-Damgård-based) is vulnerable to length-extension in constructions that use H(m) directly as MAC; use HMAC or SHA-3 family to avoid this.")
  print(" - SHA-3 (Keccak) uses sponge construction which resists length-extension and has different internal design.")








def menu():
  print("1) SHA-256 Hash Generation")
  print("2) Security Analysis Tests")
  print("3) Merkle Tree Operations")
  print("4) Quit")




def option_sha256_generation():
  while True:
      print("\n-- SHA-256 Hash Generation --")
      s = input("Enter text to hash (or 'file:<path>' to hash file, or blank to go back): ").strip()
      if s == "":
          return
      if s.startswith("file:"):
          path = s[5:]
          try:
              with open(path, 'rb') as f:
                  data = f.read()
          except Exception as e:
              print(f"Error reading file: {e}")
              continue
      else:
          data = s.encode('utf-8')
      h = sha256_hex(data)
      print(f"SHA-256: {h}")




def option_security_analysis():
  while True:
      print("\n-- Security Analysis Menu --")
      print("1) Avalanche test (default 200 trials)")
      print("2) Distribution analysis (default 2000 samples)")
      print("3) Birthday collision simulation (truncated)")
      print("4) Performance benchmark")
      print("5) Comparative example (MD5/SHA1)")
      print("6) Back")
      c = input("Choose: ").strip()
      if c == '1':
          try:
              t = int(input("Trials (Enter for 200): ") or 200)
          except:
              t = 200
          avalanche_test(trials=t)
      elif c == '2':
          try:
              s = int(input("Samples (Enter for 2000): ") or 2000)
          except:
              s = 2000
          distribution_analysis(samples=s)
      elif c == '3':
          try:
              bits = int(input("Truncation bits (Enter for 32): ") or 32)
              iters = int(input("Max iterations (Enter for 200000): ") or 200000)
          except:
              bits, iters = 32, 200000
          birthday_collision_search(trunc_bits=bits, max_iters=iters)
      elif c == '4':
          performance_benchmark()
      elif c == '5':
          comparative_analysis_example()
      elif c == '6':
          return
      else:
          print("Invalid choice.")




def option_merkle_tree():
  print("\n-- Merkle Tree Operations --")
  print("Enter data blocks (one per line). End input with an empty line.")
  blocks = []
  while True:
      line = input(f"Block {len(blocks)}> ")
      if line == "":
          break
      blocks.append(line.encode('utf-8'))
  if not blocks:
      print("No blocks provided, returning.")
      return
  tree = MerkleTree(blocks)
  root = tree.root()
  print(f"Merkle root (hex): {root.hex()}")
  while True:
      cmd = input("Commands: 'proof <index>', 'verify <index>', 'show', 'back': ").strip()
      if cmd == "back":
          return
      elif cmd == "show":
          print("Leaves (hashes):")
          for i,h in enumerate(tree.leaves_hashes):
              print(f" {i}: {h.hex()}")
          print(f"Root: {root.hex()}")
      elif cmd.startswith("proof "):
          try:
              idx = int(cmd.split()[1])
              proof = tree.get_proof(idx)
              print(f"Proof for leaf {idx} (sibling_hash, side):")
              for sh, side in proof:
                  print(f"  {side} {sh.hex()}")
          except Exception as e:
              print(f"Error: {e}")
      elif cmd.startswith("verify "):
          try:
              idx = int(cmd.split()[1])
              proof = tree.get_proof(idx)
              ok = MerkleTree.verify_proof(blocks[idx], proof, root)
              print("Verification:", "OK" if ok else "FAIL")
          except Exception as e:
              print(f"Error: {e}")
      else:
          print("Unknown command.")




def main():
  random.seed(0xC0FFEE)
  while True:
      menu()
      choice = input("Choose option: ").strip()
      if choice == '1':
          option_sha256_generation()
      elif choice == '2':
          option_security_analysis()
      elif choice == '3':
          option_merkle_tree()
      elif choice == '4' or choice.lower() in ('q','quit','exit'):
          print("Exiting...")
          sys.exit(0)
      else:
          print("Invalid choice.")




if __name__ == '__main__':
  main()

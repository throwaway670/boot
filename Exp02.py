import string
import random
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import itertools
import math
import os
import json

#==================================================CAESAR CIPHER==================================================

# ENCRYPTION
def caesar(plaintext, shift): 
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            ciphertext += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            ciphertext += char
    return ciphertext

#.................................................................................................................

# DECRYPTION USING NEGATIVE SHIFT
def caesar_decrypt(ciphertext, shift): 
    return caesar(ciphertext, -shift)

# BRUTE FORCE ATTACK ON CAESAR CIPHER
def caesar_bruteforce(ciphertext, debug=False):
    if debug: print("=== Caesar Cipher Brute Force Attack ===")
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        if debug: print(f"Shift {shift}: {decrypted}")

#.................................................................................................................

# ATTACK CAESAR CIPHER USING MULTIPLE PLAINTEXT-CIPHERTEXT PAIRS WITH THE SAME KEY.
def caeser_multiple_bruteforce(pairs):
    print("\n=== Caesar Cipher Attack (Using Multiple Pairs) ===")
    possible_shifts = list(range(26))
    for i, pair in enumerate(pairs):
        print("."*75)
        plaintext = pair['plaintext'].upper()
        ciphertext = pair['ciphertext'].upper()
        plain_chars = [c for c in plaintext if c.isalpha()]
        cipher_chars = [c for c in ciphertext if c.isalpha()]
        min_len = min(len(plain_chars), len(cipher_chars))
        plain_chars = plain_chars[:min_len]
        cipher_chars = cipher_chars[:min_len]
        pair_shifts = []
        print(f"Finding shift between Plaintext and Ciphertext characters for {i+1}...")
        for p, c in zip(plain_chars, cipher_chars):
            shift = (ord(c) - ord(p)) % 26
            pair_shifts.append(shift)
        shift_count = Counter(pair_shifts)
        most_common_shift = shift_count.most_common(1)[0][0]
        
        print(f"Pair {i+1} analysis:")
        print(f"  Most frequent shift: {most_common_shift}")
        print(f"  Shift distribution: {dict(shift_count)}")
        
        consistent_shifts = [s for s, count in shift_count.items() if count/len(pair_shifts) > 0.7]
        if consistent_shifts:
            possible_shifts = [s for s in possible_shifts if s in consistent_shifts]
            caesar_bruteforce(pair['ciphertext'])
    print("-"*75)
    print("Possible shift values across all pairs:", possible_shifts)
    
    if len(possible_shifts) == 0:
        print("No consistent shift found across pairs. Trying frequency analysis instead.")
        for pair in pairs:
            print(f"Analyzing ciphertext: {pair['ciphertext'][:50]}...")
            caesar_bruteforce(pair['ciphertext'])
    elif len(possible_shifts) == 1:
        shift = possible_shifts[0]
        print(f"Consistent shift found: {shift}")
        for pair in pairs:
            decrypted = caesar_decrypt(pair['ciphertext'], shift)
            print(f"Original: {pair['plaintext'][:50]}...")
            print(f"Decrypted: {decrypted[:50]}...")
    else:
        print("\nMultiple possible shifts found, Invalid case for Ceaser Cipher")

#==============================================MONOALPHABETIC CIPHER==============================================

# GENERATE RANDOM KEY
def monoalphabetic_key():
    letters = list(string.ascii_uppercase)
    shuffled = letters.copy()
    random.shuffle(shuffled)
    return dict(zip(letters, shuffled))

#.................................................................................................................

# ENCRYPT BY REPLACING EACH ALPHABET 
def mono_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    return ''.join(key.get(c, c) for c in plaintext)

#.................................................................................................................

# DECRYPT BY REPLACING ALPHABET BY INVERSE KEY
def mono_decrypt(ciphertext, key):
    inv_key = {v: k for k, v in key.items()}
    return ''.join(inv_key.get(c, c) for c in ciphertext)

#.................................................................................................................

# ATTACK MULTIPLE MONOALPHABETIC CIPHERS BASED IB FREQUENCY ANALYSIS
def mono_attack_multiple_pairs(pairs):
    print("\n=== Monoalphabetic Cipher Attack (Using Multiple Pairs) ===")
    
    # Combine all pairs to build a more comprehensive mapping
    combined_plaintext = ""
    combined_ciphertext = ""
    
    for pair in pairs:
        plaintext = ''.join([c for c in pair['plaintext'].upper() if c.isalpha()])
        ciphertext = ''.join([c for c in pair['ciphertext'].upper() if c.isalpha()])
        
        # Take the minimum length to ensure alignment
        min_len = min(len(plaintext), len(ciphertext))
        combined_plaintext += plaintext[:min_len]
        combined_ciphertext += ciphertext[:min_len]
    
    # Build direct mapping from known plaintext-ciphertext pairs
    direct_mapping = {}
    for p, c in zip(combined_plaintext, combined_ciphertext):
        if c in direct_mapping and direct_mapping[c] != p:
            # Skip conflicting mappings
            continue
        direct_mapping[c] = p
    
    # Fill in missing mappings using frequency analysis
    if len(direct_mapping) < 26:
        print('-'*75)
        print("Direct mapping incomplete. Using frequency analysis to fill gaps...")
        
        # English letter frequency from most common to least
        eng_freq_order = "ETAOINSRHDLUCMFYWGPBVKXQJZ"
        
        # Calculate frequency in combined ciphertext
        all_ciphertext = ''.join([c for c in combined_ciphertext if c.isalpha()])
        freq = Counter(all_ciphertext)
        
        # Sort the ciphertext letters by frequency
        cipher_freq_order = sorted(freq.keys(), key=lambda x: freq[x], reverse=True)
        
        # Map remaining letters by frequency
        for i, char in enumerate(cipher_freq_order):
            if char not in direct_mapping and i < len(eng_freq_order):
                direct_mapping[char] = eng_freq_order[i]
        print("-"*75)
    # Invert mapping for decryption (cipher->plain)
    decryption_key = {}
    for cipher_char, plain_char in direct_mapping.items():
        decryption_key[cipher_char] = plain_char
    
    print("Recovered decryption key:")
    sorted_key = sorted(decryption_key.items())
    for c, p in sorted_key:
        print(f"{c} -> {p}", end="  ")
    print()
    print("-"*75)
    # Test decryption on all pairs
    print("Testing decryption on all pairs:")
    for i, pair in enumerate(pairs):
        ciphertext = pair['ciphertext']
        decrypted = ''.join([decryption_key.get(c.upper(), c) for c in ciphertext])
        print('.'*75)
        print(f"Pair {i+1}:")
        print(f"  Original: {pair['plaintext'][:50]}")
        print(f"  Decrypted: {decrypted[:50]}")
    print("-"*75)
    # Provide the encryption key (inverse of decryption key)
    encryption_key = {v: k for k, v in decryption_key.items()}
    print("Recovered encryption key (plaintext -> ciphertext):")
    sorted_enc_key = sorted(encryption_key.items())
    for p, c in sorted_enc_key:
        print(f"{p} -> {c}", end="  ")
    print()

#=================================================PLAYFAIR CIPHER=================================================

# CREATE PLAYFAIR MATRIX USING KEY
def playfair_matrix(key):
    key = ''.join(dict.fromkeys(key.upper().replace("J", "I")))
    matrix = []
    for c in key:
        if c not in matrix:
            matrix.append(c)
    for c in string.ascii_uppercase:
        if c not in matrix and c != 'J':
            matrix.append(c)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

#.................................................................................................................

# ENCRYPT USING PLAYFAIR MATRIX
def playfair_encrypt(plaintext, key):
    matrix = playfair_matrix(key)
    plaintext = ''.join([c for c in plaintext.upper() if c.isalpha()]).replace("J", "I")
    i = 0
    digraphs = []
    while i < len(plaintext):
        a = plaintext[i]
        b = ''
        if i+1 < len(plaintext):
            b = plaintext[i+1]
        if b == a or b == '':
            b = 'X'
            i += 1
        else:
            i += 2
        digraphs.append(a+b)
    ciphertext = ''
    for a,b in digraphs:
        ax, ay = [(r,c) for r,row in enumerate(matrix) for c,ch in enumerate(row) if ch==a][0]
        bx, by = [(r,c) for r,row in enumerate(matrix) for c,ch in enumerate(row) if ch==b][0]
        if ax==bx:
            ciphertext += matrix[ax][(ay+1)%5] + matrix[bx][(by+1)%5]
        elif ay==by:
            ciphertext += matrix[(ax+1)%5][ay] + matrix[(bx+1)%5][by]
        else:
            ciphertext += matrix[ax][by] + matrix[bx][ay]
    return ciphertext

#.................................................................................................................

# DECRYPT USING PLAYFAIR MATRIX
def playfair_decrypt(ciphertext, key):
    matrix = playfair_matrix(key)
    ciphertext = ''.join([c for c in ciphertext.upper() if c.isalpha()])
    digraphs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    plaintext = ''
    for a,b in digraphs:
        ax, ay = [(r,c) for r,row in enumerate(matrix) for c,ch in enumerate(row) if ch==a][0]
        bx, by = [(r,c) for r,row in enumerate(matrix) for c,ch in enumerate(row) if ch==b][0]
        if ax==bx:
            plaintext += matrix[ax][(ay-1)%5] + matrix[bx][(by-1)%5]
        elif ay==by:
            plaintext += matrix[(ax-1)%5][ay] + matrix[(bx-1)%5][by]
        else:
            plaintext += matrix[ax][by] + matrix[bx][ay]
    return plaintext

#.................................................................................................................

# ATTACK PLAYFAIR CIPHER USING MULTIPLE PAIRS
def playfair_attack_multiple_pairs(pairs):
    print("\n=== Playfair Cipher Attack (Using Multiple Pairs) ===")
    
    # Extract digraph mappings from all pairs
    digraph_mappings = {}
    
    for pair in pairs:
        plaintext = ''.join([c for c in pair['plaintext'].upper() if c.isalpha()]).replace("J", "I")
        ciphertext = ''.join([c for c in pair['ciphertext'].upper() if c.isalpha()])
        
        # Ensure even length for digraphs
        if len(plaintext) % 2 != 0:
            plaintext += 'X'
        if len(ciphertext) % 2 != 0:
            ciphertext += 'X'
        
        # Process digraphs
        for i in range(0, min(len(plaintext), len(ciphertext)), 2):
            p_digraph = plaintext[i:i+2]
            c_digraph = ciphertext[i:i+2]
            
            # Add to mappings if not already present or conflicting
            if c_digraph not in digraph_mappings:
                digraph_mappings[c_digraph] = p_digraph
    
    print(f"Recovered {len(digraph_mappings)} digraph mappings from all pairs.")
    
    # Try common keys, scoring based on recovered digraph mappings
    common_keys = ["MONARCHY", "SECURITY", "KEYWORD", "SECRET", "CIPHER", 
                  "PLAYFAIR", "CRYPTOGRAPHY", "PASSWORD", "ALGORITHM", "COMPUTER"]
    print('-'*75)
    print("Testing common keywords:")
    best_key = None
    best_score = 0
    
    for key in common_keys:
        score = 0
        # Test this key against known digraph mappings
        for c_digraph, p_digraph in digraph_mappings.items():
            decrypted = playfair_decrypt(c_digraph, key)
            if decrypted == p_digraph:
                score += 1
        
        accuracy = score / len(digraph_mappings) if digraph_mappings else 0
        print(f"Key '{key}': matched {score}/{len(digraph_mappings)} digraphs ({accuracy:.2%})")
        
        if score > best_score:
            best_score = score
            best_key = key
    
    # Test best key on all pairs
    if best_key:
        print('-'*75)
        print(f"Best key candidate: '{best_key}' with {best_score}/{len(digraph_mappings)} matches")
        print("Testing decryption with this key:")
        print("-"*75)
        for i, pair in enumerate(pairs):
            decrypted = playfair_decrypt(pair['ciphertext'], best_key)
            print(f"Pair {i+1}:")
            print(f"  Original: {pair['plaintext'][:50]}")
            print(f"  Decrypted: {decrypted[:50]}")
            print('.'*75)
    else:
        print("\nNo key matched any digraph mappings. Attempting known plaintext attack.")
#.................................................................................................................

# HILL CIPHER KEY
def hill_key():
    print("Enter 2x2 key matrix for Hill Cipher (4 integers separated by spaces): ")
    while True:
        parts = input().split()
        if len(parts) != 4:
            print("Enter exactly 4 integers for 2x2 matrix. Try again:")
            continue
        try:
            matrix_input = list(map(int, parts))
        except ValueError:
            print("Invalid integers. Try again:")
            continue
        test_matrix = np.array(matrix_input).reshape(2, 2)
        det = int(round(np.linalg.det(test_matrix))) % 26
        if math.gcd(det, 26) == 1:
            print(f"Matrix accepted (det={det} mod 26, invertible).")
            break
        else:
            print(f"Matrix not invertible mod 26 (det={det}). Enter a different 2x2 matrix:")
    return np.array(matrix_input).reshape(2, 2)

#.................................................................................................................

# HILL CIPHER ENCRYPT
def hill_encrypt(plaintext, key_matrix):
    n = key_matrix.shape[0]
    plaintext = ''.join([c.upper() for c in plaintext if c.isalpha()])
    while len(plaintext) % n != 0:
        plaintext += 'X'
    ciphertext = ''
    for i in range(0, len(plaintext), n):
        block = np.array([ord(c)-65 for c in plaintext[i:i+n]])
        cipher_block = key_matrix.dot(block) % 26
        ciphertext += ''.join(chr(int(c)+65) for c in cipher_block)
    return ciphertext

#.................................................................................................................

# DECRYPT HILL CIPHER
def hill_decrypt(ciphertext, key_matrix):
    n = key_matrix.shape[0]
    K = np.array(key_matrix, dtype=int) % 26

    if n != 2:
        raise ValueError("hill_decrypt currently supports only 2x2 key matrices.")

    # Compute modular inverse of 2x2 matrix using adjugate and det inverse mod 26
    a, b = int(K[0, 0]), int(K[0, 1])
    c, d = int(K[1, 0]), int(K[1, 1])
    det = (a * d - b * c) % 26
    det_inv = pow(det, -1, 26)  # raises ValueError if not invertible

    adj = np.array([[d, -b], [-c, a]], dtype=int) % 26
    inv_matrix = (det_inv * adj) % 26

    # Clean ciphertext and ensure proper block sizing
    text = ''.join([ch for ch in ciphertext.upper() if ch.isalpha()])
    while len(text) % n != 0:
        text += 'X'

    plaintext = ''
    for i in range(0, len(text), n):
        block = np.array([ord(ch) - 65 for ch in text[i:i+n]], dtype=int)
        plain_block = inv_matrix.dot(block) % 26
        plaintext += ''.join(chr(int(x) + 65) for x in plain_block)
    return plaintext

#.................................................................................................................

# ATTACK HILL CIPHER PAIRS USING MULTIPLE CIPHER PAIRS
def hill_attack_multiple_pairs(pairs, n=2):
    print(f"\n=== Hill Cipher Attack (n={n}) (Using Multiple Pairs) ===")
    
    # Collect plaintext-ciphertext blocks
    p_blocks = []
    c_blocks = []
    
    for pair in pairs:
        plaintext = ''.join([c.upper() for c in pair['plaintext'] if c.isalpha()])
        ciphertext = ''.join([c.upper() for c in pair['ciphertext'] if c.isalpha()])
        
        # Process blocks of size n
        for i in range(0, min(len(plaintext), len(ciphertext)) - n + 1, n):
            p_block = [ord(plaintext[i+j]) - 65 for j in range(n)]
            c_block = [ord(ciphertext[i+j]) - 65 for j in range(n)]
            p_blocks.append(p_block)
            c_blocks.append(c_block)
    print('-'*75)
    print(f"Collected {len(p_blocks)} blocks of size {n} from all pairs.")
    print('-'*75)
    if n == 2 and len(p_blocks) >= n:
        print("Attempting to recover 2x2 key matrix...")
        
        # Try multiple combinations of blocks
        success = False
        max_attempts = min(10, len(p_blocks) * (len(p_blocks) - 1) // 2)
        attempts = 0
        
        # Try different combinations of blocks
        for i in range(len(p_blocks)):
            for j in range(i+1, len(p_blocks)):
                if attempts >= max_attempts:
                    break
                
                attempts += 1
                try:
                    # Create matrices from blocks
                    P = np.array([p_blocks[i], p_blocks[j]]).T
                    C = np.array([c_blocks[i], c_blocks[j]]).T
                    
                    # Calculate determinant of P
                    det_P = int(round(np.linalg.det(P))) % 26
                    
                    # Check if invertible mod 26
                    if math.gcd(det_P, 26) == 1:
                        # Find modular inverse of det_P
                        det_P_inv = pow(det_P, -1, 26)
                        
                        # Calculate adjugate of P
                        adj_P = np.array([[P[1, 1], -P[0, 1]], [-P[1, 0], P[0, 0]]]) % 26
                        
                        # Calculate P^(-1)
                        P_inv = (det_P_inv * adj_P) % 26
                        
                        # Calculate key matrix K
                        K = (C @ P_inv) % 26
                        print('-'*75)
                        print(f"Found invertible block combination (blocks {i} and {j})")
                        print("Recovered key matrix:")
                        print(K)
                        print('-'*75)
                        # Test the recovered key
                        print("Testing recovered key on all pairs:")
                        
                        valid_key = True
                        for idx, pair in enumerate(pairs):
                            try:
                                decrypted = hill_decrypt(pair['ciphertext'], K)
                                similarity = sum(1 for a, b in zip(decrypted.upper(), pair['plaintext'].upper()) 
                                              if a == b and a.isalpha()) / len(decrypted)
                                
                                if similarity > 0.8:  # High similarity threshold
                                    print(f"Pair {idx+1}: Good match ({similarity:.2%})")
                                    print(f"  Original: {pair['plaintext'][:50]}")
                                    print(f"  Decrypted: {decrypted[:50]}")
                                else:
                                    print(f"Pair {idx+1}: Low match ({similarity:.2%})")
                                    valid_key = False
                                    break
                                print('.'*75)
                            except:
                                print(f"Pair {idx+1}: Decryption failed")
                                valid_key = False
                                break
                        
                        if valid_key:
                            success = True
                            break
                    else:
                        if attempts == 1:  # Only print for first attempt
                            print(f"Matrix not invertible (det={det_P}). Trying other block combinations...")
                
                except Exception as e:
                    if attempts == 1:  # Only print for first attempt
                        print(f"Error with block combination {i},{j}: {e}")
            
            if success:
                break
    else:
        print(f"For {n}x{n} matrices, need at least {n} non-dependent blocks.")
        print("Falling back to brute force with common matrices...")

#=========================================POLYALPHABETIC CIPHER (VIGENERE)=========================================

# ENCRYPT
def vigenere_encrypt(plaintext, key):
    key = key.upper()
    ciphertext = ''
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            ciphertext += chr((ord(char.upper()) - 65 + k) % 26 + offset)
            key_index += 1
        else:
            ciphertext += char
    return ciphertext

#.................................................................................................................

# DECRYPT
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    plaintext = ''
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            plaintext += chr((ord(char.upper()) - 65 - k) % 26 + offset)
            key_index += 1
        else:
            plaintext += char
    return plaintext

#.................................................................................................................

def vigenere_attack(ciphertext):
    print("=== Vigenere Cipher Attack ===")
    filtered_text = ''.join(c for c in ciphertext.upper() if c.isalpha())
    print("Estimating key length using Index of Coincidence...")
    
    ic_scores = []
    max_key_length = 20
    for k in range(1, min(max_key_length + 1, len(filtered_text))):
        columns = [filtered_text[i::k] for i in range(k)]
        
        avg_ic = sum(
            sum(c * (c - 1) for c in Counter(col).values()) / (len(col) * (len(col) - 1))
            if len(col) > 1 else 0
            for col in columns
        ) / k
        ic_scores.append((k, avg_ic))
        
    ic_scores.sort(key=lambda x: x[1], reverse=True)
    
    print("\nLikely key lengths (sorted by IC):")
    for length, ic in ic_scores[:5]:
        print(f"Length {length}: IC = {ic:.4f}")

    if not ic_scores:
        print("Could not determine a likely key length.")
        return
        
    best_length = ic_scores[0][0]
    print(f"\nUsing most likely key length: {best_length}")
    
    # Step 2: Recover the key
    print("Attempting to recover key...")
    
    recovered_key = ""
    for i in range(best_length):
        column = filtered_text[i::best_length]
        most_common = Counter(column).most_common(1)
        if not most_common: continue
        
        most_common_char = most_common[0][0]
        # Assumes 'E' is the most frequent letter in English
        shift = (ord(most_common_char) - ord('E')) % 26
        recovered_key += chr(shift + ord('A'))
    
    print(f"Possible key found: {recovered_key}")
    
    # Step 3: Decrypt and show the result
    print("\nAttempting decryption with this key:")
    
    decrypted_text = ""
    key_len = len(recovered_key)
    original_text_idx = 0
    
    for char in ciphertext.upper():
        if 'A' <= char <= 'Z':
            key_shift = ord(recovered_key[original_text_idx % key_len]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - key_shift) % 26 + ord('A'))
            decrypted_text += decrypted_char
            original_text_idx += 1
        else:
            decrypted_text += char
            
    print(decrypted_text[:100] + "..." if len(decrypted_text) > 100 else decrypted_text)
    
#.................................................................................................................

# ATTACK VIGENERE CIPHER USING MULTIPLE PAIRS
def vigenere_attack_multiple_pairs(pairs):
    print("\n=== Vigenere Cipher Attack (Using Multiple Pairs) ===")
    
    # When we have plaintext-ciphertext pairs, we can directly determine the key
    possible_keys = []
    
    for pair in pairs:
        plaintext = ''.join([c.upper() for c in pair['plaintext'] if c.isalpha()])
        ciphertext = ''.join([c.upper() for c in pair['ciphertext'] if c.isalpha()])
        
        # Calculate key values
        key_values = []
        for p, c in zip(plaintext, ciphertext):
            key_val = (ord(c) - ord(p)) % 26
            key_values.append(key_val)
        
        # Try to find repeating pattern
        for key_length in range(1, 11):  # Try lengths 1-10
            if len(key_values) < key_length * 2:
                continue
                
            potential_key = key_values[:key_length]
            matches = 0
            total = 0
            
            # Check if this key length produces a repeating pattern
            for i in range(key_length, len(key_values)):
                if key_values[i] == key_values[i % key_length]:
                    matches += 1
                total += 1
            
            if total > 0 and matches / total > 0.7:  # 70% consistency
                key_chars = [chr(65 + val) for val in potential_key]
                possible_key = ''.join(key_chars)
                possible_keys.append((possible_key, matches / total))
                break
    
    # Find most consistent key
    if possible_keys:
        # Sort by match percentage
        possible_keys.sort(key=lambda x: x[1], reverse=True)
        best_key, confidence = possible_keys[0]
        print('-'*75)
        print(f"Recovered key: '{best_key}' with {confidence:.2%} confidence")
        print("-"*75)
        # Test key on all pairs
        print("Testing recovered key on all pairs:")
        for i, pair in enumerate(pairs):
            decrypted = vigenere_decrypt(pair['ciphertext'], best_key)
            print('.'*75)
            print(f"Pair {i+1}:")
            print(f"  Original: {pair['plaintext'][:50]}")
            print(f"  Decrypted: {decrypted[:50]}")
    else:
        print("\nNo consistent key pattern found across pairs.")
        print("Falling back to traditional Kasiski/IC analysis...")
        
        # Combine all ciphertexts for better frequency analysis
        combined_ciphertext = ''.join([pair['ciphertext'] for pair in pairs])
        vigenere_attack(combined_ciphertext)

#==============================================RELATIVE FREQUENCY PLOT=============================================
def plot_frequency(text, filename="./Exp02-RelFrequency.pdf"):
    text = ''.join([c.upper() for c in text if c.isalpha()])
    freq = Counter(text)
    letters = list(string.ascii_uppercase)
    counts = [freq.get(c,0) for c in letters]
    
    plt.figure(figsize=(12,6))
    plt.bar(letters, counts)
    plt.title("Relative Frequency of Letters")
    plt.xlabel("Letters")
    plt.ylabel("Frequency")
    plt.savefig(filename)
    plt.show()

#==================================GENERATE PLAINTEXT-CIPHERTEXT PAIRS=============================================
def generate_pairs():
    # Create a directory to store the pairs
    os.makedirs("cipher_pairs", exist_ok=True)
    
    # Sample plaintexts of varying lengths
    plaintexts = [
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        "CRYPTOGRAPHY AND NETWORK SECURITY IS GOOD SUBJECT",
        "IS ANYONE EVEN GOING TO CHECK THIS",
        "THIS IS A TOTALLY RANDOM PLAINTEXT FOR TESTING",
        "HELLO WORLD THIS IS A SIMPLE TEST CASE FOR CIPHERS"
    ]
    
    pairs = {
        "caesar": [],
        "monoalphabetic": [],
        "playfair": [],
        "hill": [],
        "vigenere": []
    }
    
    print("\n=== Generating Plaintext-Ciphertext Pairs ===")
    
    # Generate Caesar pairs
    print("Generating Caesar pairs...")
    shift = int(input("Enter Caesar Shift Key: "))
    for text in plaintexts:
        cipher = caesar(text, shift)
        pairs["caesar"].append({
            "plaintext": text,
            "ciphertext": cipher,
            "key": shift
        })
    
    # Generate Monoalphabetic pairs
    print("Generating Monoalphabetic pairs...")
    key = monoalphabetic_key()
    print("Monoalphabetic Key is randomly created")
    for text in plaintexts:
        cipher = mono_encrypt(text, key)
        pairs["monoalphabetic"].append({
            "plaintext": text,
            "ciphertext": cipher,
            "key": key
        })
    
    # Generate Playfair pairs
    print("Generating Playfair pairs...")
    key = input("Enter Keyword for Playfair Cipher: ")
    for i, text in enumerate(plaintexts):
        cipher = playfair_encrypt(text, key)
        pairs["playfair"].append({
            "plaintext": text,
            "ciphertext": cipher,
            "key": key
        })
    
    # Generate Hill pairs (using 2x2 matrices)
    print("Generating Hill pairs...")
    # Generate random invertible 2x2 matrix
    matrix = hill_key()
    for text in plaintexts:
        cipher = hill_encrypt(text, matrix)
        pairs["hill"].append({
            "plaintext": text,
            "ciphertext": cipher,
            "key": matrix.tolist()
        })
    
    # Generate Vigenere pairs
    print("Generating Vigenere pairs...")
    key = input("Enter Vigenère Cipher key: ")
    for i, text in enumerate(plaintexts):
        cipher = vigenere_encrypt(text, key)
        pairs["vigenere"].append({
            "plaintext": text,
            "ciphertext": cipher,
            "key": key
        })
    
    # Save complete pairs (with keys) for your reference
    with open("./cipher_pairs/pairswithkey.json", "w") as f:
        json.dump(pairs, f, indent=2)
    
    # Save pairs without keys to attack
    shared_pairs = {}
    for cipher_type, cipher_pairs in pairs.items():
        shared_pairs[cipher_type] = [
            {"plaintext": p["plaintext"], "ciphertext": p["ciphertext"]} 
            for p in cipher_pairs
        ]
    
    with open("./cipher_pairs/pairswithoutkey.json", "w") as f:
        json.dump(shared_pairs, f, indent=2)
    print("-"*75)
    print("Pairs generated and saved to 'cipher_pairs' directory:")
    print("1. pairswithkey.json - contains your keys (keep private)")
    print("2. pairswithoutkey.json - for attacking")

#===================================DEMONSTRATION OF ATTACKS ON CIPHERS============================================
def attack_ciphers(file_path):
    try:
        with open(file_path, "r") as f:
            unknownpairs = json.load(f)
        
        print("\n=== Attacking Ciphers (Using Multiple Pairs) ===")
        
        # Attack Caesar ciphers
        if "caesar" in unknownpairs:
            caeser_multiple_bruteforce(unknownpairs["caesar"])
        
        # Attack Monoalphabetic ciphers
        if "monoalphabetic" in unknownpairs:
            mono_attack_multiple_pairs(unknownpairs["monoalphabetic"])
        
        # Attack Playfair ciphers
        if "playfair" in unknownpairs:
            playfair_attack_multiple_pairs(unknownpairs["playfair"])
        
        # Attack Hill ciphers
        if "hill" in unknownpairs:
            hill_attack_multiple_pairs(unknownpairs["hill"], 2)
        
        # Attack Vigenere ciphers
        if "vigenere" in unknownpairs:
            vigenere_attack_multiple_pairs(unknownpairs["vigenere"])
                
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except json.JSONDecodeError:
        print(f"Error parsing JSON in file: {file_path}")
    except Exception as e:
        print(f"Error: {e}")

#=====================================================MAIN MENU====================================================
def main_menu():
    while True:
        print("\n=== Substitution Cipher Experiment ===")
        print("1. Encrypt and Decrypt text with all cipher methods")
        print("2. Generate cipher pairs")
        print("3. Attack all unknown ciphers from file")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            print("-"*75)
            plaintext = input("Enter text you want to encrypt: ")
            print("-"*75)
            shift = int(input("Enter Caesar Shift Key: "))
            print("Monoalphabetic Key is randomly created")
            keyword = input("Enter Keyword for Playfair Cipher: ")
            key_matrix = hill_key()
            vig_key = input("Enter Vigenère Cipher key: ")
            print("-"*75)

            caesar_cipher = caesar(plaintext, shift)
            print("Caesar Cipher:", caesar_cipher)
            print("Caesar Key (Shift):", shift)
            print("Caesar Decrypted:", caesar_decrypt(caesar_cipher, shift))
            print('.'*75)
            mono_key = monoalphabetic_key()
            mono_cipher = mono_encrypt(plaintext, mono_key)
            print("Monoalphabetic Cipher:", mono_cipher)
            print("Monoalphabetic Key:", mono_key)
            print("Monoalphabetic Decrypted:", mono_decrypt(mono_cipher, mono_key))
            print('.'*75)
            playfair_cipher = playfair_encrypt(plaintext, keyword)
            print("Playfair Cipher:", playfair_cipher)
            print("Playfair Key (Keyword):", keyword)
            print("Playfair Decrypted:", playfair_decrypt(playfair_cipher, keyword))
            print('.'*75)
            hill_cipher = hill_encrypt(plaintext, key_matrix)
            print("Hill Cipher:", hill_cipher)
            print(f"Hill Key (2x2 Matrix): {key_matrix.tolist()}")
            print("Hill Decrypted:", hill_decrypt(hill_cipher, key_matrix))
            print('.'*75)
            vig_cipher = vigenere_encrypt(plaintext, vig_key)
            print("\nVigenere Cipher:", vig_cipher)
            print("Vigenere Key:", vig_key)
            print("Vigenere Decrypted:", vigenere_decrypt(vig_cipher, vig_key))
            print('-'*75)
            print("Generating Relative Frequency Plot...")
            plot_frequency(plaintext)
            print("-"*75)
            
        elif choice == '2':
            generate_pairs()
            
        elif choice == '3':
            file_path = "./cipher_pairs/pairswithoutkey.json"
            attack_ciphers(file_path)
            
        elif choice == '4':
            print("Exiting program. Goodbye!")
            break
            
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main_menu()
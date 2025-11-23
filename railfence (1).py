def encryptRailFence(text, key):
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    
    row = 0
    down = True

    # Fill the rails in zig-zag
    for col in range(len(text)):
        rail[row][col] = text[col]

        if row == key - 1:
            down = False
        elif row == 0:
            down = True

        row += 1 if down else -1

    # Construct ciphertext
    result = ""
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result += rail[i][j]
    return result


def decryptRailFence(cipher, key):
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]

    # Mark the zig-zag positions
    row = 0
    down = True
    for col in range(len(cipher)):
        rail[row][col] = '*'

        if row == key - 1:
            down = False
        elif row == 0:
            down = True

        row += 1 if down else -1

    # Fill the characters in zig-zag order
    idx = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and idx < len(cipher):
                rail[i][j] = cipher[idx]
                idx += 1

    # Read plaintext in zig-zag order
    result = ""
    row = 0
    down = True
    for col in range(len(cipher)):
        result += rail[row][col]

        if row == key - 1:
            down = False
        elif row == 0:
            down = True

        row += 1 if down else -1

    return result


# Main Program
if __name__ == "__main__":
    key = int(input("Enter key (number of rails): "))
    text = input("Enter text: ")

    print("\n1. Encrypt\n2. Decrypt")
    choice = int(input("Choose option: "))

    if choice == 1:
        encrypted = encryptRailFence(text, key)
        print("\nEncrypted Text:", encrypted)
    elif choice == 2:
        decrypted = decryptRailFence(text, key)
        print("\nDecrypted Text:", decrypted)
    else:
        print("Invalid choice")

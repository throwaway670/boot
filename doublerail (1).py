def encryptDoubleRail(text):
    rail1 = ""
    rail2 = ""

    # Distribute characters alternately
    for i in range(len(text)):
        if i % 2 == 0:
            rail1 += text[i]
        else:
            rail2 += text[i]

    # Concatenate both
    cipher = rail1 + rail2
    return cipher


def decryptDoubleRail(cipher):
    mid = (len(cipher) + 1) // 2  # Split position

    rail1 = cipher[:mid]
    rail2 = cipher[mid:]

    result = ""
    r1 = r2 = 0

    # Reconstruct text by alternating characters
    for i in range(len(cipher)):
        if i % 2 == 0:
            result += rail1[r1]
            r1 += 1
        else:
            result += rail2[r2]
            r2 += 1

    return result


# Main Program
if __name__ == "__main__":
    text = input("Enter text: ")

    print("\n1. Encrypt\n2. Decrypt")
    choice = int(input("Choose option: "))

    if choice == 1:
        cipher = encryptDoubleRail(text)
        print("\nEncrypted Text:", cipher)
    elif choice == 2:
        decrypted = decryptDoubleRail(text)
        print("\nDecrypted Text:", decrypted)
    else:
        print("Invalid choice!")

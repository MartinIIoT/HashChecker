import hashlib
import sys
import os

def get_hash(filePath, hashType):
    # Generate HASH from file
    with open(filePath, 'rb') as f:
        data = f.read()
        if hashType == 64:
            hash = hashlib.sha256(data).hexdigest()
        elif hashType == 128:
            hash = hashlib.sha512(data).hexdigest()
        else:
            hash = 101
    return hash


def highlight_differences(a, b):
    highlighted = []
    for char_a, char_b in zip(a, b):
        if char_a == char_b:
            highlighted.append(char_a)
        else:
            highlighted.append(f"\033[91m{char_a}\033[0m")
    return "".join(highlighted)


def compare_hash(knownHash=1, fileHash=2, typeHash=64):
    textHash = "SHA256" if typeHash == 64 else "SHA512"

    if knownHash == fileHash:
        print()
        print(f"File {textHash}:\t{fileHash}")
        print(f"Known {textHash}:\t{knownHash}")
        print(f"Compare:\tOK")
        print()
    else:
        print()
        print(f"File {textHash}:\t{highlight_differences(fileHash, knownHash)}")
        print(f"Known {textHash}:\t{highlight_differences(knownHash, fileHash)}")
        print(f"Compare:\tNOK")
        print()


def verify_hash(file_path, known_hash):
    if not os.path.exists(file_path):
        print()
        print("File not exists.")
        print()
        return
    
    # Get known HASH
    known_hash = known_hash.lower()

    # Get HASH from file
    if len(known_hash) == 64:
        file_hash = get_hash(file_path, 64)
        compare_hash(known_hash, file_hash, 64)
    elif len(known_hash) == 128:
        file_hash = get_hash(file_path, 128)
        compare_hash(known_hash, file_hash, 128)
    else:
        print(f"Invalid known HASH.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Please add 2 parameters: 1. path to file 2. known hash.")
    else:
        file_path = sys.argv[1]
        known_hash = sys.argv[2]
        verify_hash(file_path, known_hash)

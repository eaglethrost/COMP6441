import hashlib
import numpy as np
from itertools import product

no_lines = 10
no_last_digits = 2

def getSHA256hash(content):
    sha256 = hashlib.sha256()
    sha256.update(content.encode())
    return sha256.hexdigest()

def generate_combinations(n):
    characters = '01'
    all_combinations = [''.join(combination) for combination in product(characters, repeat=n)]
    return all_combinations

def modify_text(lines, binary):
    i = 1
    lines = np.copy(lines)
    while (i < no_lines):
        if binary[-i] == "1":
            lines[i-1] = lines[i-1].rstrip("\n") + " " + "\n"
        i += 1
    newText = ''.join(lines)
    return newText

def print_hash(fakeHash, fakeText, binary):
    print(f"Fake Hash: {fakeHash}")
    print(f"Binary Combination: {binary}")
    print("Fake Text:")
    print(fakeText)    

def birthday_attack(fakeLines, realHash):
    binCombinations = generate_combinations(no_lines)
    for combination in binCombinations:
        newFake = modify_text(fakeLines, combination)
        newFakeHash = getSHA256hash(newFake)
        if realHash == newFakeHash[-no_last_digits:]:
            print_hash(newFakeHash, newFake, combination)
            return

if __name__ == "__main__":
    # 1. Generate hash of real text
    real_text = ""
    with open("real.txt", "r") as f:
        real_text = f.read()
    realHash = getSHA256hash(real_text)
    endHash = realHash[-no_last_digits:]
    print(f"Real hash: {realHash}")
    
    # 2. Input fake text
    fake_text_lines = []
    with open("fake.txt","r") as f:
        fake_text_lines = f.readlines()

    # 3. Generate binary permutations of length 10 until fake text has same hash real text
    birthday_attack(fake_text_lines, endHash)

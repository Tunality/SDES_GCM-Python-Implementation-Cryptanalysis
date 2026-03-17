def run_attack(cipher_blocks):
    print("\n[!] Running Bit-Flipping Attack...")
    modified_cipher = [block[:] for block in cipher_blocks]
    # Flip the very first bit of the first block
    modified_cipher[0][0] ^= 1
    print("Modified first bit of ciphertext. This should cause a GCM Auth failure.")
    return modified_cipher
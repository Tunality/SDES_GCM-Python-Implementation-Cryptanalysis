def run_attack(cipher1, cipher2, original_plaintext):
    print("\n[!] EXPLOITING Nonce Reuse...")
    # Since C1 ^ C2 = P1 ^ P2, then (C1 ^ C2) ^ P1 = P2
    
    recovered_p2 = ""
    for i in range(min(len(cipher1), len(cipher2))):
        # XOR the two cipher blocks
        diff = [cipher1[i][j] ^ cipher2[i][j] for j in range(8)]
        # XOR with the known plaintext bits of the first message
        p1_bits = [int(b) for b in format(ord(original_plaintext[i]), '08b')]
        p2_bits = [diff[j] ^ p1_bits[j] for j in range(8)]
        # Convert back to character
        recovered_p2 += chr(int("".join(map(str, p2_bits)), 2))
    
    print(f"SUCCESS! Using only the first message, we recovered the second: '{recovered_p2}'")
    print("Notice: We never used the 10-bit Key to do this.")
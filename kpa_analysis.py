def run_analysis(plaintext_str, cipher_blocks, iv, sdes_encrypt_func, gcm_decrypt_func):
    print("\n[!] Analysis: Enhanced KPA & Candidate Verification")
    
    # 1. Recover the actual keystream used for the first block (P ^ C = Keystream)
    pt_bits = [int(b) for b in format(ord(plaintext_str[0]), '08b')]
    actual_keystream = [pt_bits[i] ^ cipher_blocks[0][i] for i in range(8)]
    print(f"Recovered actual keystream from known char '{plaintext_str[0]}': {actual_keystream}")

    # 2. Find keys that generate this keystream and test them
    candidates = []
    print(f"\nScanning key space for matches...")
    
    for i in range(1024):
        k = [int(b) for b in format(i, '010b')]
        # Check if this key generates the same keystream at the given IV
        generated_ks = sdes_encrypt_func(iv, k)
        
        if generated_ks == actual_keystream:
            # Test the key immediately
            test_dec = gcm_decrypt_func(cipher_blocks, k, iv)
            candidates.append(("".join(map(str, k)), test_dec))
    
    print(f"\nFound {len(candidates)} candidate keys:")
    for idx, (k_str, result_text) in enumerate(candidates):
        # Display the key alongside its result
        print(f"[{idx+1}] Candidate Key: {k_str} | Result: {result_text}")
    
    choice = int(input("\nSelect the correct result number: "))
    return candidates[choice - 1][0], candidates[choice - 1][1]
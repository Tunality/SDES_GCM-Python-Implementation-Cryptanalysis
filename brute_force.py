import main # We will name your main file sdes_core.py

def run_attack(cipher_blocks, target_tag, iv, decrypt_func, encrypt_func):
    print("\n[!] Starting Brute Force Attack...")
    matches = []
    for i in range(1024):
        candidate_key = [int(b) for b in format(i, '010b')]
        h_key = encrypt_func([0]*8, candidate_key)
        
        # Check Tag
        tag = [0] * 8
        for block in cipher_blocks:
            tag = [tag[j] ^ block[j] for j in range(8)]
            tag = [tag[j] ^ h_key[j] for j in range(8)]
            
        if tag == target_tag:
            text = decrypt_func(cipher_blocks, candidate_key, iv)
            if all(32 <= ord(c) <= 126 for c in text):
                matches.append(("".join(map(str, candidate_key)), text))

    if not matches:
        return None, None

    for idx, (k, txt) in enumerate(matches):
        print(f"[{idx + 1}] Key: {k} | Result: {txt}")
    
    choice = 1 if len(matches) == 1 else int(input("Select number: "))
    return matches[choice - 1]
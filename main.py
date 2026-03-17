import brute_force
import nonce_attack
import bit_flip
import kpa_analysis
import linear_analysis
import side_channel

# --- S-DES CORE FUNCTIONS ---

def key_generation(key):
    p10 = [key[2], key[4], key[1], key[6], key[3], key[9], key[0], key[8], key[7], key[5]]
    k1, ls1 = k1_generation(p10)
    k2 = k2_generation(ls1)
    return k1, k2

def k1_generation(p10):
    ls1_1 = [p10[1], p10[2], p10[3], p10[4], p10[0]]
    ls1_2 = [p10[6], p10[7], p10[8], p10[9], p10[5]]
    ls1 = ls1_1 + ls1_2
    p8 = [ls1[5], ls1[2], ls1[6], ls1[3], ls1[7], ls1[4], ls1[9], ls1[8]]
    return p8, ls1

def k2_generation(ls1):
    ls2_1 = [ls1[2], ls1[3], ls1[4], ls1[0], ls1[1]]
    ls2_2 = [ls1[7], ls1[8], ls1[9], ls1[5], ls1[6]]
    ls2 = ls2_1 + ls2_2
    p8 = [ls2[5], ls2[2], ls2[6], ls2[3], ls2[7], ls2[4], ls2[9], ls2[8]]
    return p8

def sbox(bits, box):
    row = int(f"{bits[0]}{bits[3]}", 2)
    col = int(f"{bits[1]}{bits[2]}", 2)
    val = box[row][col]
    return [int(b) for b in format(val, '02b')]

def fk(bits, key):
    L, R = bits[:4], bits[4:]
    ep = [R[3], R[0], R[1], R[2], R[1], R[2], R[3], R[0]]
    xor_res = [ep[i] ^ key[i] for i in range(8)]
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
    f_out = sbox(xor_res[:4], S0) + sbox(xor_res[4:], S1)
    p4 = [f_out[1], f_out[3], f_out[2], f_out[0]]
    return [L[i] ^ p4[i] for i in range(4)] + R

def sdes_encrypt(block, key):
    k1, k2 = key_generation(key)
    ip = [block[1], block[5], block[2], block[0], block[3], block[7], block[4], block[6]]
    step1 = fk(ip, k1)
    sw = step1[4:] + step1[:4]
    step2 = fk(sw, k2)
    return [step2[3], step2[0], step2[2], step2[4], step2[6], step2[1], step2[7], step2[5]]

# --- GCM MODE FUNCTIONS ---

def xor_bits(a, b):
    return [i ^ j for i, j in zip(a, b)]

def ghash(cipher_blocks, h_key):
    tag = [0] * 8
    for block in cipher_blocks:
        tag = xor_bits(tag, block)
        tag = xor_bits(tag, h_key)
    return tag

def sdes_gcm_encrypt(text, key_bits, iv):
    h_key = sdes_encrypt([0]*8, key_bits)
    cipher_blocks = []
    counter = iv[:]
    for char in text:
        pb = [int(b) for b in format(ord(char), '08b')]
        ks = sdes_encrypt(counter, key_bits)
        cipher_blocks.append(xor_bits(pb, ks))
        c_val = (int("".join(map(str, counter)), 2) + 1) % 256
        counter = [int(x) for x in format(c_val, '08b')]
    tag = ghash(cipher_blocks, h_key)
    return cipher_blocks, tag

def sdes_gcm_decrypt(cipher_blocks, key_bits, iv):
    chars = []
    counter = iv[:]
    for block in cipher_blocks:
        ks = sdes_encrypt(counter, key_bits)
        pb = xor_bits(block, ks)
        chars.append(chr(int("".join(map(str, pb)), 2)))
        c_val = (int("".join(map(str, counter)), 2) + 1) % 256
        counter = [int(x) for x in format(c_val, '08b')]
    return "".join(chars)

def main():
    print("--- S-DES GCM System ---")
    pt = input("Enter String: ")
    k_str = input("Enter 10-bit Key: ")
    key = [int(b) for b in k_str]
    iv = [0] * 8
    
    c_blocks, tag = sdes_gcm_encrypt(pt, key, iv)
    print(f"\nEncryption Complete.")
    print(f"Ciphertext: {c_blocks[:2]}...")
    print(f"Auth Tag: {tag}")

    while True:
        print("\n--- MENU ---")
        print("1. Decrypt (Standard)")
        print("2. Brute Force Attack")
        print("3. Nonce Reuse Attack (Requires 2nd message)")
        print("4. Bit-Flip Attack (Integrity Test)")
        print("5. KPA and Tag Collision Analysis")
        print("6. Linear Cryptanalysis Summary")
        print("7. Side-Channel Timing Test")
        print("0. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            print(f"Result: {sdes_gcm_decrypt(c_blocks, key, iv)}")
        
        elif choice == '2':
            f_key, f_text = brute_force.run_attack(c_blocks, tag, iv, sdes_gcm_decrypt, sdes_encrypt)
            print(f"Attack Result -> Key: {f_key}, Text: {f_text}")
            
        elif choice == '3':
            pt2 = input("Enter a second string to encrypt with SAME key/IV: ")
            c2, t2 = sdes_gcm_encrypt(pt2, key, iv)
            # Pass the original plaintext to show the exploit
            nonce_attack.run_attack(c_blocks, c2, pt)

        elif choice == '4':
            mod_cipher = bit_flip.run_attack(c_blocks)
            # Try to decrypt and check tag
            h_key = sdes_encrypt([0]*8, key)
            new_tag = ghash(mod_cipher, h_key)
            print(f"Original Tag: {tag}")
            print(f"New Tag:      {new_tag}")
            if new_tag != tag:
                print("SUCCESS: GCM detected tampering! Tag mismatch.")
            else:
                print("FAILURE: Tampering not detected.")
        elif choice == '5':
            # Enhanced KPA with inline results
            final_k, final_pt = kpa_analysis.run_analysis(pt, c_blocks, iv, sdes_encrypt, sdes_gcm_decrypt)
            print(f"\n[+] KPA SUCCESS!")
            print(f"Confirmed Key: {final_k}")
            print(f"Full Plaintext: {final_pt}")

        elif choice == '6':
            linear_analysis.run_analysis()

        elif choice == '7':
            side_channel.run_analysis(sdes_encrypt, [0]*8, key)

        elif choice == '0':
            print("Terminating...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
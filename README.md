# S-DES GCM Cryptanalysis Sandbox

A modular Python implementation of the Simplified Data Encryption Standard (S-DES) operating in Galois/Counter Mode (GCM). This project is designed to demonstrate both the mechanics of authenticated encryption and various methods of cryptanalysis.

## 🚀 Features
- **Full S-DES Implementation:** Manual bit-level permutations and S-Box logic.
- **GCM Integration:** Provides Authenticated Encryption with Associated Data (AEAD) logic using CTR mode and GHASH.
- **Attack Suite:** - **Brute Force:** Breaks the 10-bit key space.
    - **Known-Plaintext Attack (KPA):** Recovers keystreams from known characters.
    - **Nonce Reuse Exploit:** Recovers plaintext without the key if an IV is reused.
    - **Bit-Flipping:** Demonstrates GCM's integrity protection.
    - **Linear Cryptanalysis:** Maps S-Box biases using Linear Approximation Tables.

## 📁 Project Structure
- `main.py`: The central controller and interactive menu.
- `brute_force.py`: Logic for key recovery and heuristic filtering.
- `nonce_attack.py`: Demonstrates the "Forbidden Attack" on reused IVs.
- `kpa_analysis.py`: Keystream recovery and candidate verification.
- `linear_analysis.py`: S-Box bias mapping.
- `bit_flip.py`: Integrity and GHASH verification.
- `side_channel.py`: Timing-based vulnerability analysis.

## 🛠️ Usage
1. Clone the repository.
2. Run the main script:
   ```bash
   python main.py

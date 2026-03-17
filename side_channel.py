import time

def run_analysis(encrypt_func, block, key):
    print("\n[!] Analysis: Side-Channel (Timing)")
    start = time.perf_counter()
    for _ in range(1000):
        encrypt_func(block, key)
    end = time.perf_counter()
    print(f"Time for 1000 encryptions: {end - start:.6f} seconds")
    print("Vulnerability: Variation in processing time can leak bits of the secret key.")